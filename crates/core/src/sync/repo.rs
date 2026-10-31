//! Reading a folder from GitHub or GitLab: its files (the git tree) and each file's bytes (git
//! blobs, base64 in JSON, so images survive hosts that pass answers on as text).
//!
//! Docs: https://docs.github.com/en/rest/git/trees#get-a-tree, https://docs.github.com/en/rest/git/blobs#get-a-blob,
//! https://docs.gitlab.com/api/repositories/#list-repository-tree, https://docs.gitlab.com/api/repositories/#get-a-blob-from-repository

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::connect::providers::{github, gitlab};
use crate::connect::{HttpCall, HttpReply, http_error};

/// GitLab lists a tree 100 entries a page, without saying how many pages there are in the body;
/// a sync asks for this many at once.
pub const GITLAB_PAGES: usize = 10;
const GITLAB_PER_PAGE: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Provider {
    GitHub,
    GitLab,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Provider> {
        match s.trim().to_ascii_lowercase().as_str() {
            "github" => Some(Provider::GitHub),
            "gitlab" => Some(Provider::GitLab),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Provider::GitHub => "github",
            Provider::GitLab => "gitlab",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Provider::GitHub => "GitHub",
            Provider::GitLab => "GitLab",
        }
    }
}

/// A folder on a branch of a repository. Every part was checked before it was saved.
#[derive(Clone, Debug, PartialEq)]
pub struct Repo {
    pub provider: Provider,
    /// `github.com`, `gitlab.com` or a self-managed GitLab's host.
    pub host: String,
    /// `owner/name`, or a GitLab project's full path.
    pub repo: String,
    pub branch: String,
    /// Without slashes at either end; empty for the whole repository.
    pub folder: String,
    /// GitLab: the project's id, when it's known (sources read through DumbSlab's GitLab app).
    /// Reads go by it, not by the path: a rename or transfer changes the path, and another project
    /// may take the old one. Without it (a token), reads follow the path.
    pub project_id: Option<i64>,
}

/// A file in the folder.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Within the folder, e.g. `guides/setup.md`.
    pub path: String,
    /// The git blob id.
    pub sha: String,
    /// In bytes; GitLab's listing doesn't say.
    pub size: Option<u64>,
}

/// Percent-encodes every byte but unreserved ones.
fn enc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// Percent-encodes each segment of a path, keeping the slashes.
fn enc_path(p: &str) -> String {
    p.split('/').map(enc).collect::<Vec<_>>().join("/")
}

/// A git object id: 40 (SHA-1) or 64 (SHA-256) hex digits.
pub fn valid_sha(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A branch name git and the APIs accept, without characters that would change the request
/// (`:` names a path in a GitHub tree, `?` and `#` would end the path).
pub fn valid_branch(b: &str) -> bool {
    (1..=200).contains(&b.len())
        && !b.starts_with(['-', '/', '.'])
        && !b.ends_with(['/', '.'])
        && !b.ends_with(".lock")
        && !b.contains("..")
        && !b.contains("//")
        && !b.contains("@{")
        && b.chars().all(|c| !c.is_control() && !c.is_whitespace() && !matches!(c, ':' | '?' | '*' | '[' | '\\' | '^' | '~' | '#' | '%'))
}

/// A folder within the repository: segments without `.`, `..` or characters that would change
/// the request. Returns it without slashes at either end.
pub fn valid_folder(f: &str) -> Option<String> {
    let f = f.trim().trim_matches('/');
    if f.is_empty() {
        return Some(String::new());
    }
    let ok = f.len() <= 500
        && f.split('/').all(|s| {
            !s.is_empty() && s != "." && s != ".." && s.chars().all(|c| !c.is_control() && !matches!(c, ':' | '?' | '#' | '\\' | '%'))
        });
    ok.then(|| f.to_string())
}

/// `owner/name` from what someone typed: the path itself or the repository's address.
pub fn github_repo(typed: &str) -> Result<String, String> {
    let t = typed.trim().trim_end_matches('/');
    let path = t.strip_prefix("https://github.com/").or_else(|| t.strip_prefix("http://github.com/")).unwrap_or(t);
    let mut parts = path.split('/');
    let (owner, name) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default().trim_end_matches(".git"));
    let rest: Vec<&str> = parts.collect();
    // An address may go on into the repository (`/tree/main/docs`); a bare path may not.
    if github::valid_owner(owner) && github::valid_repo(name) && (rest.is_empty() || path.len() != t.len()) {
        Ok(format!("{owner}/{name}"))
    } else {
        Err(format!("The repository should look like `owner/name` or https://github.com/owner/name; `{typed}` doesn't."))
    }
}

/// (host, project path) from what someone typed: a project's path (on `host`) or its address.
pub fn gitlab_project(typed: &str, host: &str) -> Result<(String, String), String> {
    let t = typed.trim().trim_end_matches('/');
    let (host, path) = match t.strip_prefix("https://") {
        Some(rest) => {
            let (h, p) = rest.split_once('/').unwrap_or((rest, ""));
            // `…/group/project/-/tree/main` names the project before `/-/`.
            (gitlab::valid_host(&format!("https://{h}"))?, p.split("/-/").next().unwrap_or_default().to_string())
        }
        None => (gitlab::valid_host(host)?, t.to_string()),
    };
    let path = path.trim_end_matches(".git").to_string();
    let segments: Vec<&str> = path.split('/').collect();
    if (2..=20).contains(&segments.len()) && segments.iter().all(|s| gitlab::valid_segment(s)) {
        Ok((host, path))
    } else {
        Err(format!("The project should look like `group/project` or its address on GitLab; `{typed}` doesn't."))
    }
}

impl Repo {
    /// e.g. `acme/docs` or `acme/docs/handbook` (with the folder).
    pub fn label(&self) -> String {
        if self.folder.is_empty() { self.repo.clone() } else { format!("{}/{}", self.repo, self.folder) }
    }

    /// A path within the folder, as a path within the repository.
    pub fn repo_path(&self, path: &str) -> String {
        if self.folder.is_empty() { path.to_string() } else { format!("{}/{path}", self.folder) }
    }

    fn get(&self, url: String, token: &str) -> HttpCall {
        let call = match self.provider {
            Provider::GitHub => {
                HttpCall::get(url).header("accept", "application/vnd.github+json").header("x-github-api-version", "2022-11-28")
            }
            Provider::GitLab => HttpCall::get(url).header("accept", "application/json"),
        };
        let call = call.header("user-agent", "DumbSlab");
        if token.is_empty() { call } else { call.bearer(token) }
    }

    fn gitlab_project_url(&self) -> String {
        match self.project_id {
            Some(id) => format!("https://{}/api/v4/projects/{id}", self.host),
            None => format!("https://{}/api/v4/projects/{}", self.host, enc(&self.repo)),
        }
    }

    /// GitLab, by the project's id: the request for the project itself, whose answer says its
    /// path now ([`Repo::read_path`]).
    pub fn project_call(&self, token: &str) -> Option<HttpCall> {
        (self.provider == Provider::GitLab && self.project_id.is_some()).then(|| self.get(self.gitlab_project_url(), token))
    }

    /// The project's path now (`path_with_namespace`), from the answer to [`Repo::project_call`],
    /// when it's this project's answer.
    pub fn read_path(&self, reply: &HttpReply) -> Option<String> {
        let v = reply.json();
        if !reply.ok() || self.project_id.is_none() || v["id"].as_i64() != self.project_id {
            return None;
        }
        gitlab_project(v["path_with_namespace"].as_str()?, "").ok().map(|(_, path)| path)
    }

    /// The requests that list the folder's files.
    pub fn tree_calls(&self, token: &str) -> Vec<HttpCall> {
        match self.provider {
            // `branch:folder` names the folder's own tree, so a large repository's other files
            // don't count against GitHub's limit on one answer.
            Provider::GitHub => {
                let treeish = if self.folder.is_empty() { self.branch.clone() } else { format!("{}:{}", self.branch, self.folder) };
                vec![self.get(format!("https://api.github.com/repos/{}/git/trees/{}?recursive=1", self.repo, enc(&treeish)), token)]
            }
            Provider::GitLab => (1..=GITLAB_PAGES)
                .map(|page| {
                    let path = if self.folder.is_empty() { String::new() } else { format!("&path={}", enc(&self.folder)) };
                    let url = format!(
                        "{}/repository/tree?ref={}&recursive=true&per_page={GITLAB_PER_PAGE}&page={page}{path}",
                        self.gitlab_project_url(),
                        enc(&self.branch)
                    );
                    self.get(url, token)
                })
                .collect(),
        }
    }

    fn error(&self, reply: &HttpReply, has_token: bool) -> String {
        let name = self.provider.name();
        match reply.status {
            404 => format!(
                "{name} has no branch `{}`{} in {}, or {}. Check the branch and folder.",
                self.branch,
                if self.folder.is_empty() { String::new() } else { format!(" with a folder `{}`", self.folder) },
                self.repo,
                if has_token { "the token can't read the repository" } else { "the repository is private: add a token" }
            ),
            401 => format!("{name} rejected the token. Check that it was copied whole and hasn't expired, then save it again."),
            403 if !has_token => {
                format!(
                    "{name} refused: the repository may be private, or {name}'s limit for requests without a token was reached. Add a token."
                )
            }
            _ => http_error(name, reply),
        }
    }

    /// The folder's files, from the answers to [`Repo::tree_calls`].
    pub fn read_tree(&self, replies: &[HttpReply], has_token: bool) -> Result<Vec<Entry>, String> {
        match self.provider {
            Provider::GitHub => {
                let r = replies.first().cloned().unwrap_or_default();
                if !r.ok() {
                    return Err(self.error(&r, has_token));
                }
                let v = r.json();
                if v["truncated"].as_bool() == Some(true) {
                    return Err(format!("{} has too many files for GitHub to list at once. Choose a smaller folder.", self.label()));
                }
                let Some(tree) = v["tree"].as_array() else {
                    return Err("GitHub's answer had no file list. Try again.".into());
                };
                Ok(tree
                    .iter()
                    .filter(|e| e["type"] == "blob")
                    .filter_map(|e| entry(e["path"].as_str()?, e["sha"].as_str()?, e["size"].as_u64()))
                    .collect())
            }
            Provider::GitLab => {
                let mut out = vec![];
                let mut last_full = false;
                for r in replies {
                    if !r.ok() {
                        return Err(self.error(r, has_token));
                    }
                    let v = r.json();
                    let Some(page) = v.as_array() else {
                        return Err("GitLab's answer had no file list. Try again.".into());
                    };
                    last_full = page.len() >= GITLAB_PER_PAGE;
                    let prefix = if self.folder.is_empty() { String::new() } else { format!("{}/", self.folder) };
                    out.extend(page.iter().filter(|e| e["type"] == "blob").filter_map(|e| {
                        let path = e["path"].as_str()?.strip_prefix(prefix.as_str())?;
                        entry(path, e["id"].as_str()?, None)
                    }));
                }
                if last_full {
                    return Err(format!(
                        "{} has more than {} files and folders, more than a sync lists from GitLab. Choose a smaller folder.",
                        self.label(),
                        GITLAB_PAGES * GITLAB_PER_PAGE
                    ));
                }
                Ok(out)
            }
        }
    }

    /// The request for one file's bytes.
    pub fn blob_call(&self, sha: &str, token: &str) -> HttpCall {
        match self.provider {
            Provider::GitHub => self.get(format!("https://api.github.com/repos/{}/git/blobs/{sha}", self.repo), token),
            Provider::GitLab => self.get(format!("{}/repository/blobs/{sha}", self.gitlab_project_url()), token),
        }
    }

    /// One file's bytes, from the answer to [`Repo::blob_call`].
    pub fn read_blob(&self, reply: &HttpReply, has_token: bool) -> Result<Vec<u8>, String> {
        if !reply.ok() {
            return Err(self.error(reply, has_token));
        }
        let v = reply.json();
        let content = match (&v["content"], v["encoding"].as_str()) {
            (Value::String(c), Some("base64")) => c,
            _ => return Err("the file was too large to read, or the answer was cut short".into()),
        };
        let compact: String = content.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        STANDARD.decode(compact.as_bytes()).map_err(|_| "the file's contents couldn't be read".to_string())
    }

    /// The folder on GitHub or GitLab.
    pub fn folder_url(&self) -> String {
        let mut url = format!("{}/tree/{}", self.web_base(), enc_path(&self.branch));
        if !self.folder.is_empty() {
            url.push('/');
            url.push_str(&enc_path(&self.folder));
        }
        url
    }

    fn web_base(&self) -> String {
        match self.provider {
            Provider::GitHub => format!("https://github.com/{}", self.repo),
            Provider::GitLab => format!("https://{}/{}/-", self.host, self.repo),
        }
    }

    /// A file on GitHub or GitLab, by its path in the repository: its page, or its bytes (`raw`).
    pub fn file_url(&self, repo_path: &str, raw: bool) -> String {
        format!("{}/{}/{}/{}", self.web_base(), if raw { "raw" } else { "blob" }, enc_path(&self.branch), enc_path(repo_path))
    }
}

fn entry(path: &str, sha: &str, size: Option<u64>) -> Option<Entry> {
    (valid_sha(sha) && !path.is_empty()).then(|| Entry { path: path.to_string(), sha: sha.to_ascii_lowercase(), size })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gh() -> Repo {
        Repo {
            provider: Provider::GitHub,
            host: "github.com".into(),
            repo: "acme/docs".into(),
            branch: "main".into(),
            folder: "handbook".into(),
            project_id: None,
        }
    }

    #[test]
    fn names_are_checked() {
        assert_eq!(github_repo("acme/docs").unwrap(), "acme/docs");
        assert_eq!(github_repo("https://github.com/acme/docs.git").unwrap(), "acme/docs");
        assert_eq!(github_repo("https://github.com/acme/docs/tree/main/handbook").unwrap(), "acme/docs");
        for bad in ["acme", "acme/..", "acme/docs/extra", "https://evil.test/acme/docs", "ac me/docs"] {
            assert!(github_repo(bad).is_err(), "{bad}");
        }
        assert_eq!(gitlab_project("group/sub/project", "").unwrap(), ("gitlab.com".into(), "group/sub/project".into()));
        assert_eq!(gitlab_project("https://git.example.com/a/b/-/tree/main", "").unwrap(), ("git.example.com".into(), "a/b".into()));
        assert!(gitlab_project("https://10.0.0.1/a/b", "").is_err(), "IP addresses are refused");
        assert!(gitlab_project("solo", "").is_err());
        assert!(valid_branch("main") && valid_branch("release/2.0") && valid_branch("feature-x"));
        for bad in ["", "a b", "a:b", "a..b", "-x", "x/", "x.lock", "a?b", "a#b", "a%2Fb"] {
            assert!(!valid_branch(bad), "{bad}");
        }
        assert_eq!(valid_folder("/docs/guides/").as_deref(), Some("docs/guides"));
        assert_eq!(valid_folder("").as_deref(), Some(""));
        for bad in ["docs/../x", "a//b", "a:b", "./a", "a?b"] {
            assert!(valid_folder(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn requests_and_links() {
        let r = gh();
        let calls = r.tree_calls("tok");
        assert_eq!(calls[0].url, "https://api.github.com/repos/acme/docs/git/trees/main%3Ahandbook?recursive=1");
        assert!(calls[0].headers.contains(&("authorization".into(), "Bearer tok".into())));
        assert!(r.tree_calls("")[0].headers.iter().all(|(k, _)| k != "authorization"), "public repositories go without a token");
        assert_eq!(r.file_url("handbook/a b.md", false), "https://github.com/acme/docs/blob/main/handbook/a%20b.md");
        assert_eq!(r.file_url("img/x.png", true), "https://github.com/acme/docs/raw/main/img/x.png");
        let gl = Repo {
            provider: Provider::GitLab,
            host: "gitlab.com".into(),
            repo: "g/p".into(),
            branch: "main".into(),
            folder: String::new(),
            project_id: None,
        };
        let calls = gl.tree_calls("t");
        assert_eq!(calls.len(), GITLAB_PAGES);
        assert_eq!(calls[1].url, "https://gitlab.com/api/v4/projects/g%2Fp/repository/tree?ref=main&recursive=true&per_page=100&page=2");
        assert_eq!(gl.file_url("README.md", false), "https://gitlab.com/g/p/-/blob/main/README.md");
        assert_eq!(gl.folder_url(), "https://gitlab.com/g/p/-/tree/main");
        assert!(gl.project_call("t").is_none(), "a token source follows the path");

        // Known by id (DumbSlab's GitLab app): reads go by it; links use the path.
        let by_id = Repo { project_id: Some(3), ..gl };
        assert_eq!(
            by_id.tree_calls("t")[0].url,
            "https://gitlab.com/api/v4/projects/3/repository/tree?ref=main&recursive=true&per_page=100&page=1"
        );
        assert_eq!(
            by_id.blob_call(&"a".repeat(40), "t").url,
            format!("https://gitlab.com/api/v4/projects/3/repository/blobs/{}", "a".repeat(40))
        );
        assert_eq!(by_id.project_call("t").unwrap().url, "https://gitlab.com/api/v4/projects/3");
        assert_eq!(by_id.file_url("README.md", false), "https://gitlab.com/g/p/-/blob/main/README.md");
        let answer =
            |id: i64, path: &str| HttpReply { status: 200, body: serde_json::json!({ "id": id, "path_with_namespace": path }).to_string() };
        assert_eq!(by_id.read_path(&answer(3, "g/moved")).as_deref(), Some("g/moved"));
        assert_eq!(by_id.read_path(&answer(4, "g/p")), None, "another project's answer");
        assert_eq!(by_id.read_path(&HttpReply { status: 404, body: "{}".into() }), None);
    }

    #[test]
    fn trees_and_blobs_are_read() {
        let r = gh();
        let sha = "a".repeat(40);
        let tree = serde_json::json!({ "tree": [
            { "path": "a.md", "type": "blob", "sha": sha, "size": 12 },
            { "path": "img", "type": "tree", "sha": sha },
            { "path": "bad.md", "type": "blob", "sha": "nope" },
        ] });
        let entries = r.read_tree(&[HttpReply { status: 200, body: tree.to_string() }], true).unwrap();
        assert_eq!(entries, vec![Entry { path: "a.md".into(), sha: sha.clone(), size: Some(12) }]);
        assert!(r.read_tree(&[HttpReply { status: 404, body: "{}".into() }], true).unwrap_err().contains("no branch `main`"));
        let truncated = serde_json::json!({ "tree": [], "truncated": true });
        assert!(r.read_tree(&[HttpReply { status: 200, body: truncated.to_string() }], true).is_err());
        let blob = serde_json::json!({ "content": "aGVs\nbG8=\n", "encoding": "base64" });
        assert_eq!(r.read_blob(&HttpReply { status: 200, body: blob.to_string() }, true).unwrap(), b"hello");
        let cut = HttpReply { status: 200, body: "{\"content\": \"aGVs".into() };
        assert!(r.read_blob(&cut, true).is_err());
    }
}
