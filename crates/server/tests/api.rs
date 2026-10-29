//! End-to-end tests through the real request path (routing, auth, transactions, SQLite).

use base64::Engine;
use dumbslab::store::Store;
use dumbslab_core::{Effect, HostConfig, Request};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct H {
    store: Store,
    cfg: HostConfig,
    _dir: tempfile::TempDir,
}

#[derive(Clone)]
enum Auth {
    None,
    Bearer(String),
    Cookie(String),
}

struct Res {
    status: u16,
    body: Value,
    headers: Vec<(String, String)>,
    effects: Vec<Effect>,
}

impl Res {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        self.body.as_str().map(String::from).unwrap_or_default()
    }
}

impl H {
    fn new() -> H {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        H {
            store,
            cfg: HostConfig { base_url: Some("https://kb.test".into()), setup_token: Some("SETUP".into()), open_setup: false },
            _dir: dir,
        }
    }

    fn raw(&self, method: &str, path_q: &str, body: Vec<u8>, content_type: &str, auth: &Auth) -> Res {
        let (path, query) = path_q.split_once('?').unwrap_or((path_q, ""));
        let mut headers =
            vec![("content-type".to_string(), content_type.to_string()), ("x-dumbslab-client".to_string(), "web".to_string())];
        match auth {
            Auth::None => {}
            Auth::Bearer(t) => headers.push(("authorization".into(), format!("Bearer {t}"))),
            Auth::Cookie(c) => headers.push(("cookie".into(), format!("dumbslab_session={c}"))),
        }
        let req = Request {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers,
            body,
            origin: "https://kb.test".into(),
            client_ip: None,
        };
        let out = self
            .store
            .with_tx(|db| {
                let o = dumbslab_core::handle(db, &self.cfg, &req).expect("core route");
                let c = o.commit;
                (o, c)
            })
            .unwrap();
        let ct = out.response.headers.iter().find(|(k, _)| k == "content-type").map(|(_, v)| v.clone()).unwrap_or_default();
        let body = if ct.contains("json") {
            serde_json::from_slice(&out.response.body).unwrap_or(Value::Null)
        } else {
            Value::String(String::from_utf8_lossy(&out.response.body).into_owned())
        };
        Res { status: out.response.status, body, headers: out.response.headers, effects: out.effects }
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>, auth: &Auth) -> Res {
        let bytes = body.map(|b| serde_json::to_vec(&b).unwrap()).unwrap_or_default();
        self.raw(method, path, bytes, "application/json", auth)
    }

    fn ok(&self, method: &str, path: &str, body: Option<Value>, auth: &Auth) -> Value {
        let r = self.call(method, path, body, auth);
        assert_eq!(r.status, 200, "{method} {path} → {} {}", r.status, r.body);
        r.body
    }

    fn mcp(&self, auth: &Auth, toolset: &str, msg: Value) -> Res {
        let path = if toolset.is_empty() { "/mcp".to_string() } else { format!("/mcp?toolset={toolset}") };
        self.call("POST", &path, Some(msg), auth)
    }

    /// Runs setup and returns (admin cookie, admin token).
    fn setup(&self) -> (Auth, Auth) {
        let r = self.call(
            "POST",
            "/api/v1/auth/setup",
            Some(json!({ "setup_token": "SETUP", "workspace_name": "Acme", "name": "Ada Admin", "email": "ada@acme.test", "password": "correct horse" })),
            &Auth::None,
        );
        assert_eq!(r.status, 200, "{}", r.body);
        let cookie = session_from(&r);
        let token =
            self.ok("POST", "/api/v1/tokens", Some(json!({ "name": "admin", "scopes": ["read", "write", "admin"] })), &cookie)["token"]
                .as_str()
                .unwrap()
                .to_string();
        (cookie, Auth::Bearer(token))
    }

    /// Creates a user and a read/write token for them.
    fn user(&self, admin: &Auth, email: &str, name: &str, role: &str) -> (String, Auth) {
        let u =
            self.ok("POST", "/api/v1/users", Some(json!({ "email": email, "name": name, "role": role, "password": "password123" })), admin);
        let id = u["user"]["id"].as_str().unwrap().to_string();
        let t = self.ok("POST", "/api/v1/tokens", Some(json!({ "name": "t", "user": id })), admin);
        (id, Auth::Bearer(t["token"].as_str().unwrap().to_string()))
    }
}

fn session_from(r: &Res) -> Auth {
    let cookie = r.header("set-cookie").expect("set-cookie");
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    Auth::Cookie(value.to_string())
}

fn ids(list: &Value) -> Vec<String> {
    list["items"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap().to_string()).collect()
}

#[test]
fn setup_login_and_csrf() {
    let h = H::new();
    let state = h.ok("GET", "/api/v1/auth/state", None, &Auth::None);
    assert_eq!(state["needs_setup"], true);
    let bad = h.call(
        "POST",
        "/api/v1/auth/setup",
        Some(json!({ "setup_token": "nope", "name": "x", "email": "x@y.z", "password": "password123" })),
        &Auth::None,
    );
    assert_eq!(bad.status, 403);

    let (cookie, _) = h.setup();
    let again = h.call(
        "POST",
        "/api/v1/auth/setup",
        Some(json!({ "setup_token": "SETUP", "name": "x", "email": "x@y.z", "password": "password123" })),
        &Auth::None,
    );
    assert_eq!(again.status, 409);

    // Seeded content exists.
    let posts = h.ok("GET", "/api/v1/posts", None, &cookie);
    assert_eq!(posts["items"].as_array().unwrap().len(), 2);

    // Cookie writes need the CSRF header.
    let Auth::Cookie(c) = &cookie else { unreachable!() };
    assert_eq!(h.call("POST", "/api/v1/topics", Some(json!({ "name": "x" })), &Auth::None).status, 401);
    let req = Request {
        method: "POST".into(),
        path: "/api/v1/topics".into(),
        headers: vec![("cookie".into(), format!("dumbslab_session={c}")), ("content-type".into(), "application/json".into())],
        body: br#"{"name":"x"}"#.to_vec(),
        origin: "https://kb.test".into(),
        ..Default::default()
    };
    let out = h.store.with_tx(|db| (dumbslab_core::handle(db, &h.cfg, &req).unwrap(), true)).unwrap();
    assert_eq!(out.response.status, 403);

    // A cross-site form can't log the victim into another account (login CSRF).
    let forged_login = Request {
        method: "POST".into(),
        path: "/api/v1/auth/login".into(),
        headers: vec![("content-type".into(), "text/plain".into())],
        body: br#"{"email":"ada@acme.test","password":"correct horse"}"#.to_vec(),
        origin: "https://kb.test".into(),
        ..Default::default()
    };
    let out = h.store.with_tx(|db| (dumbslab_core::handle(db, &h.cfg, &forged_login).unwrap(), true)).unwrap();
    assert_eq!(out.response.status, 403);

    // Login: wrong password, then right one; throttled after repeated failures.
    let wrong = h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "ada@acme.test", "password": "wrong password" })), &Auth::None);
    assert_eq!(wrong.status, 401);
    let right = h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "ADA@acme.test", "password": "correct horse" })), &Auth::None);
    assert_eq!(right.status, 200, "{}", right.body);
    assert!(right.header("set-cookie").unwrap().contains("Secure"));
    for _ in 0..10 {
        h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "ghost@acme.test", "password": "nopenope" })), &Auth::None);
    }
    let throttled = h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "ghost@acme.test", "password": "nopenope" })), &Auth::None);
    assert_eq!(throttled.status, 429);

    // Logout ends the session.
    let session = session_from(&right);
    h.ok("POST", "/api/v1/auth/logout", None, &session);
    assert_eq!(h.call("GET", "/api/v1/me", None, &session).status, 401);
}

#[test]
fn drafts_private_topics_and_roles() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, member) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (viewer_id, viewer) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");

    // Drafts are private to the author (and admins).
    let draft = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Secret plan", "content": "draft body" })), &member);
    let id = draft["id"].as_str().unwrap().to_string();
    assert_eq!(draft["status"], "draft");
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &viewer).status, 404);
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &admin).status, 200);
    h.ok("PATCH", &format!("/api/v1/posts/{id}"), Some(json!({ "status": "published" })), &member);
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &viewer).status, 200);

    // Viewers can't write posts but can comment and react.
    assert_eq!(h.call("POST", "/api/v1/posts", Some(json!({ "title": "x" })), &viewer).status, 403);
    assert_eq!(h.call("PATCH", &format!("/api/v1/posts/{id}"), Some(json!({ "title": "y" })), &viewer).status, 403);
    h.ok("POST", &format!("/api/v1/posts/{id}/comments"), Some(json!({ "body": "Looks good" })), &viewer);
    h.ok("POST", "/api/v1/reactions", Some(json!({ "target_type": "post", "target_id": id, "emoji": "👍" })), &viewer);

    // Private topics hide their posts from non-members everywhere.
    let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Leadership", "visibility": "private" })), &admin);
    let tid = topic["id"].as_str().unwrap().to_string();
    assert_eq!(h.call("GET", &format!("/api/v1/topics/{tid}"), None, &member).status, 404);
    assert_eq!(h.call("POST", "/api/v1/posts", Some(json!({ "title": "x", "topic_ids": [tid] })), &member).status, 404);
    h.ok("POST", &format!("/api/v1/topics/{tid}/members"), Some(json!({ "user": "mia@acme.test" })), &admin);
    let hidden = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Compensation bands", "content": "zebracorn salary ranges", "topic_ids": [tid], "status": "published" })),
        &member,
    );
    let hid = hidden["id"].as_str().unwrap().to_string();
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{hid}"), None, &viewer).status, 404);
    assert!(!ids(&h.ok("GET", "/api/v1/posts", None, &viewer)).contains(&hid));
    assert!(h.ok("GET", "/api/v1/search?q=zebracorn", None, &viewer)["items"].as_array().unwrap().is_empty());
    assert_eq!(h.ok("GET", "/api/v1/search?q=zebracorn", None, &member)["items"].as_array().unwrap().len(), 1);
    let feed = h.ok("GET", "/api/v1/activity?limit=200", None, &viewer);
    assert!(feed["items"].as_array().unwrap().iter().all(|a| a["post_id"] != json!(hid)));
    assert!(feed["items"].as_array().unwrap().iter().all(|a| a["event"] != "token.created"), "admin-only events leak");
    let topics = h.ok("GET", "/api/v1/topics", None, &viewer);
    assert!(!ids(&topics).contains(&tid));
    // Deleting the private topic would orphan (and expose) its posts, so it's refused.
    assert_eq!(h.call("DELETE", &format!("/api/v1/topics/{tid}"), None, &admin).status, 409);

    // Mentioning the viewer in the private post doesn't notify them.
    h.ok("POST", &format!("/api/v1/posts/{hid}/edit"), Some(json!({ "edits": [{ "type": "append", "content": "cc @vic" }] })), &member);
    let n = h.ok("GET", "/api/v1/notifications", None, &viewer);
    assert!(n["items"].as_array().unwrap().iter().all(|x| x["post"]["id"] != json!(hid)));

    // Editing a post never drops private topics the editor can't see (B-S3).
    let shared_post = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Cross-listed", "content": "x", "topic_ids": [tid], "status": "published" })),
        &admin,
    );
    let cid = shared_post["id"].as_str().unwrap().to_string();
    let public_topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Everyone" })), &admin)["id"].as_str().unwrap().to_string();
    h.ok("PATCH", &format!("/api/v1/posts/{cid}"), Some(json!({ "add_topic_ids": [public_topic] })), &admin);
    let (_, outsider) = h.user(&admin, "otto@acme.test", "Otto", "member");
    let other_topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Elsewhere" })), &admin)["id"].as_str().unwrap().to_string();
    h.ok("PATCH", &format!("/api/v1/posts/{cid}"), Some(json!({ "topic_ids": [public_topic, other_topic] })), &outsider);
    h.ok("PATCH", &format!("/api/v1/posts/{cid}"), Some(json!({ "add_topic_ids": [other_topic] })), &outsider);
    let topics_now: Vec<String> = h.ok("GET", &format!("/api/v1/posts/{cid}"), None, &admin)["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect();
    assert!(topics_now.contains(&tid), "private topic was dropped: {topics_now:?}");

    // Insights totals don't count private comments (B-S5).
    h.ok("POST", &format!("/api/v1/posts/{hid}/comments"), Some(json!({ "body": "secret thread" })), &admin);
    let seen_by_admin = h.ok("GET", "/api/v1/insights", None, &admin)["counts"]["comments"].as_i64().unwrap();
    let seen_by_viewer = h.ok("GET", "/api/v1/insights", None, &viewer)["counts"]["comments"].as_i64().unwrap();
    assert!(seen_by_viewer < seen_by_admin, "viewer {seen_by_viewer} vs admin {seen_by_admin}");

    // Losing access to a post also hides its notifications (S2).
    let shared = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Roadmap", "content": "hi @vic", "status": "published" })), &member);
    let sid = shared["id"].as_str().unwrap().to_string();
    let has_notice = |h: &H| {
        h.ok("GET", "/api/v1/notifications", None, &viewer)["items"].as_array().unwrap().iter().any(|x| x["post"]["id"] == json!(sid))
    };
    assert!(has_notice(&h));
    h.ok("PATCH", &format!("/api/v1/posts/{sid}"), Some(json!({ "topic_ids": [tid], "title": "Roadmap (confidential)" })), &member);
    assert!(!has_notice(&h));
    assert_eq!(h.ok("GET", "/api/v1/notifications?unread_only=true", None, &viewer)["unread_count"], 0);

    // Purging a private post doesn't announce its title to everyone (S1).
    h.ok("DELETE", &format!("/api/v1/posts/{sid}?permanent=true"), None, &admin);
    let feed = h.ok("GET", "/api/v1/activity?limit=200", None, &viewer);
    assert!(feed["items"].as_array().unwrap().iter().all(|a| !a["summary"].as_str().unwrap().contains("Roadmap")));

    // Deleting a private topic doesn't reveal its earlier events (S3).
    let secret = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Project Falcon", "visibility": "private" })), &admin);
    let fid = secret["id"].as_str().unwrap();
    h.ok("PATCH", &format!("/api/v1/topics/{fid}"), Some(json!({ "description": "acquisition" })), &admin);
    h.ok("DELETE", &format!("/api/v1/topics/{fid}"), None, &admin);
    let feed = h.ok("GET", "/api/v1/activity?limit=200", None, &viewer);
    assert!(feed["items"].as_array().unwrap().iter().all(|a| !a["summary"].as_str().unwrap().contains("Falcon")));

    // Admins keep the full history of deleted topics (S11).
    let admin_feed = h.ok("GET", "/api/v1/activity?limit=200", None, &admin);
    assert!(admin_feed["items"].as_array().unwrap().iter().any(|a| a["summary"].as_str().unwrap().contains("Falcon")));

    // Breadcrumbs don't reveal a private parent (S5).
    let child = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Public child", "parent_id": tid })), &admin);
    let crumbs = h.ok("GET", &format!("/api/v1/topics/{}", child["id"].as_str().unwrap()), None, &viewer);
    assert!(crumbs["breadcrumbs"].as_array().unwrap().is_empty());

    // Scopes and admin-only operations.
    let ro =
        h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "ro", "scopes": ["read"] })), &member)["token"].as_str().unwrap().to_string();
    let ro = Auth::Bearer(ro);
    assert_eq!(h.call("GET", "/api/v1/posts", None, &ro).status, 200);
    assert_eq!(h.call("POST", "/api/v1/topics", Some(json!({ "name": "nope" })), &ro).status, 403);
    assert_eq!(h.call("POST", "/api/v1/users", Some(json!({ "email": "e@e.ee", "name": "E" })), &member).status, 403);
    assert_eq!(h.call("POST", "/api/v1/tokens", Some(json!({ "name": "x", "scopes": ["admin"] })), &member).status, 403);
    assert_eq!(h.call("POST", "/api/v1/tokens", Some(json!({ "name": "x", "scopes": ["read", "write"] })), &ro).status, 403);
    assert_eq!(h.call("PATCH", &format!("/api/v1/users/{viewer_id}"), Some(json!({ "name": "Hacked" })), &member).status, 403);

    // Deactivated users' tokens stop working; the last admin can't be demoted.
    h.ok("PATCH", &format!("/api/v1/users/{viewer_id}"), Some(json!({ "deactivated": true })), &admin);
    assert_eq!(h.call("GET", "/api/v1/me", None, &viewer).status, 401);
    let me = h.ok("GET", "/api/v1/me", None, &admin);
    let admin_id = me["user"]["id"].as_str().unwrap();
    assert_eq!(h.call("PATCH", &format!("/api/v1/users/{admin_id}"), Some(json!({ "role": "member" })), &admin).status, 409);
}

#[test]
fn post_lifecycle_history_and_edits() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, member) = h.user(&admin, "mia@acme.test", "Mia", "member");
    let (vic_id, viewer) = h.user(&admin, "vic@acme.test", "Vic", "viewer");
    let _ = vic_id;

    let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Engineering", "icon": "🛠" })), &admin);
    let tid = topic["id"].as_str().unwrap();
    h.ok("POST", "/api/v1/follows", Some(json!({ "target_type": "topic", "target_id": tid })), &viewer);

    let a = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Deploy guide", "content": "# Deploy\n\n## Setup\n\nInstall the CLI.\n\n## Release\n\nRun deploy.\n", "topic_ids": [tid], "status": "published" })),
        &member,
    );
    let aid = a["id"].as_str().unwrap().to_string();
    assert_eq!(a["version"], 1);
    assert_eq!(a["outline"].as_array().unwrap().len(), 3);
    // Topic followers hear about new posts.
    let n = h.ok("GET", "/api/v1/notifications", None, &viewer);
    assert!(n["items"].as_array().unwrap().iter().any(|x| x["kind"] == "new_post"));

    // Section edit and find/replace.
    let edited = h.ok(
        "POST",
        &format!("/api/v1/posts/{aid}/edit"),
        Some(json!({ "base_version": 1, "edits": [
            { "type": "replace_section", "heading": "Setup", "content": "Install the CLI with brew." },
            { "type": "replace", "find": "Run deploy.", "replace": "Run `deploy --prod`." }
        ]})),
        &admin,
    );
    assert_eq!(edited["version"], 2);
    assert!(edited["content"].as_str().unwrap().contains("Install the CLI with brew.\n\n## Release"));
    // Stale writes are refused.
    let stale = h.call("PATCH", &format!("/api/v1/posts/{aid}"), Some(json!({ "base_version": 1, "content": "clobber" })), &member);
    assert_eq!(stale.status, 409);
    assert_eq!(stale.body["error"]["details"]["current_version"], 2);
    let bad_edit = h.call(
        "POST",
        &format!("/api/v1/posts/{aid}/edit"),
        Some(json!({ "edits": [{ "type": "replace", "find": "nowhere", "replace": "x" }] })),
        &member,
    );
    assert_eq!(bad_edit.status, 400);

    // History, diff and restore.
    let versions = h.ok("GET", &format!("/api/v1/posts/{aid}/versions"), None, &member);
    assert_eq!(versions["items"].as_array().unwrap().len(), 2);
    let diff = h.ok("GET", &format!("/api/v1/posts/{aid}/diff"), None, &member);
    assert!(diff["diff"].as_str().unwrap().contains("+Install the CLI with brew."));
    assert_eq!(diff["from"], 1);
    let restored = h.ok("POST", &format!("/api/v1/posts/{aid}/versions/1/restore"), None, &member);
    assert_eq!(restored["version"], 3);
    assert!(restored["content"].as_str().unwrap().contains("Install the CLI.\n"));

    // Backlinks and verification.
    let b = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Onboarding", "content": format!("See the [deploy guide](/p/{aid}/deploy-guide)."), "status": "published" })),
        &member,
    );
    let a_now = h.ok("GET", &format!("/api/v1/posts/{aid}"), None, &viewer);
    assert_eq!(a_now["backlinks"][0]["id"], b["id"]);
    let verified = h.ok("POST", &format!("/api/v1/posts/{aid}/verify"), Some(json!({ "expires_in_days": 30 })), &member);
    assert_eq!(verified["verification"]["status"], "verified");
    let verified_list = h.ok("GET", "/api/v1/posts?verification=verified", None, &member);
    assert_eq!(ids(&verified_list), vec![aid.clone()]);

    // Trash and restore; only author or admin may delete.
    assert_eq!(h.call("DELETE", &format!("/api/v1/posts/{}", b["id"].as_str().unwrap()), None, &admin).status, 200);
    assert_eq!(h.call("DELETE", &format!("/api/v1/posts/{aid}"), None, &viewer).status, 403);
    h.ok("DELETE", &format!("/api/v1/posts/{aid}"), None, &member);
    assert!(!ids(&h.ok("GET", "/api/v1/posts", None, &member)).contains(&aid));
    assert!(ids(&h.ok("GET", "/api/v1/posts?status=trash", None, &member)).contains(&aid));
    assert!(h.ok("GET", "/api/v1/search?q=deploy", None, &member)["items"].as_array().unwrap().iter().all(|x| x["post_id"] != json!(aid)));
    h.ok("POST", &format!("/api/v1/posts/{aid}/restore"), None, &member);
    assert!(!h.ok("GET", "/api/v1/search?q=deploy", None, &member)["items"].as_array().unwrap().is_empty());

    // Permanent delete needs an admin scope and removes everything.
    assert_eq!(h.call("DELETE", &format!("/api/v1/posts/{aid}?permanent=true"), None, &member).status, 403);
    h.ok("DELETE", &format!("/api/v1/posts/{aid}?permanent=true"), None, &admin);
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{aid}"), None, &admin).status, 404);
}

#[test]
fn search_ranks_titles_and_supports_prefixes() {
    let h = H::new();
    let (_, admin) = h.setup();
    h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Kubernetes runbook", "content": "pods and nodes", "status": "published" })),
        &admin,
    );
    h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Office wifi", "content": "We might move to kubernetes someday.", "status": "published" })),
        &admin,
    );
    let r = h.ok("GET", "/api/v1/search?q=kubernetes", None, &admin);
    let titles: Vec<&str> = r["items"].as_array().unwrap().iter().map(|x| x["title"].as_str().unwrap()).collect();
    assert_eq!(titles[0], "Kubernetes runbook");
    assert!(titles.contains(&"Office wifi"));
    let prefix = h.ok("GET", "/api/v1/search?q=kuber", None, &admin);
    assert_eq!(prefix["items"].as_array().unwrap().len(), 2);
    let snippet = prefix["items"][1]["snippet"].as_str().unwrap();
    assert!(snippet.contains("<mark>"), "{snippet}");
    // No AND match falls back to any word.
    let broad = h.ok("GET", "/api/v1/search?q=pods%20zzzqqq", None, &admin);
    assert_eq!(broad["broadened"], true);
    let page1 = h.ok("GET", "/api/v1/search?q=kubernetes%20zzzqqq&limit=1&types=post", None, &admin);
    assert_eq!(page1["broadened"], true);
    let cursor = page1["next_cursor"].as_str().unwrap();
    let page2 = h.ok("GET", &format!("/api/v1/search?q=kubernetes%20zzzqqq&limit=1&types=post&cursor={cursor}"), None, &admin);
    assert_eq!(page2["items"].as_array().unwrap().len(), 1, "second page of broadened results");
    // Types filter and odd input.
    let topics_only = h.ok("GET", "/api/v1/search?q=getting&types=topic", None, &admin);
    assert!(topics_only["items"].as_array().unwrap().iter().all(|x| x["kind"] == "topic"));
    assert!(h.ok("GET", "/api/v1/search?q=%22%29%3B%20--", None, &admin)["items"].as_array().unwrap().is_empty());
}

#[test]
fn mcp_tools_and_rollback() {
    let h = H::new();
    let (_, admin) = h.setup();
    let init = h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "1" } } }));
    assert_eq!(init.body["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).status, 202);

    let tools = h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })).body;
    let all = tools["result"]["tools"].as_array().unwrap();
    assert!(all.len() > 50);
    for t in all {
        assert_eq!(t["inputSchema"]["type"], "object", "{}", t["name"]);
        assert_eq!(t["outputSchema"]["type"], "object", "{}", t["name"]);
        let name = t["name"].as_str().unwrap();
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 64);
    }

    let created = h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "create_post", "arguments": { "title": "From an agent", "content": "Hello", "status": "published" } } }));
    let result = &created.body["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["title"], "From an agent");
    let pid = result["structuredContent"]["id"].as_str().unwrap().to_string();
    let feed = h.ok("GET", &format!("/api/v1/activity?post_id={pid}"), None, &admin);
    assert_eq!(feed["items"][0]["via"], "mcp");

    // A failing tool call rolls back its partial writes.
    let before = h.ok("GET", "/api/v1/posts?status=all&limit=200", None, &admin)["items"].as_array().unwrap().len();
    let failed = h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "create_post", "arguments": { "title": "Orphan", "topic_ids": ["doesnotexist"] } } }));
    assert_eq!(failed.body["result"]["isError"], true);
    let after = h.ok("GET", "/api/v1/posts?status=all&limit=200", None, &admin)["items"].as_array().unwrap().len();
    assert_eq!(before, after);
    let drafts = h.ok("GET", "/api/v1/posts?status=draft", None, &admin);
    assert!(drafts["items"].as_array().unwrap().iter().all(|p| p["title"] != "Orphan"));

    h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.test/in" })), &admin);
    let partial = h.mcp(
        &admin,
        "",
        json!({ "jsonrpc": "2.0", "id": 41, "method": "tools/call", "params": { "name": "import_documents", "arguments": {
        "documents": [{ "title": "Good", "content": "ok" }, { "title": "  ", "content": "bad" }] } } }),
    );
    assert_eq!(partial.body["result"]["isError"], true);
    assert!(partial.effects.is_empty(), "rolled-back call must not send webhooks");
    let none_scope =
        h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "none", "scopes": [] })), &admin)["token"].as_str().unwrap().to_string();
    let res = h.mcp(
        &Auth::Bearer(none_scope),
        "",
        json!({ "jsonrpc": "2.0", "id": 42, "method": "resources/read", "params": { "uri": format!("dumbslab://posts/{pid}") } }),
    );
    assert!(res.body["error"].is_object(), "{}", res.body);

    let unknown = h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": { "name": "nope" } }));
    assert_eq!(unknown.body["error"]["code"], -32602);
    assert_eq!(h.mcp(&admin, "", json!([{ "jsonrpc": "2.0", "id": 6, "method": "ping" }])).status, 400);

    // Read-only tokens only see read tools; the core toolset can reach everything via call_operation.
    let ro =
        h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "ro", "scopes": ["read"] })), &admin)["token"].as_str().unwrap().to_string();
    let ro = Auth::Bearer(ro);
    let ro_tools = h.mcp(&ro, "", json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" })).body;
    assert!(ro_tools["result"]["tools"].as_array().unwrap().iter().all(|t| t["annotations"]["readOnlyHint"] == true));
    let core = h.mcp(&admin, "core", json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/list" })).body;
    assert!(core["result"]["tools"].as_array().unwrap().len() < 20);
    let via_call = h.mcp(&admin, "core", json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": { "name": "call_operation", "arguments": { "name": "verify_post", "arguments": { "id": pid } } } }));
    assert_eq!(via_call.body["result"]["structuredContent"]["verification"]["status"], "verified");

    let guide =
        h.mcp(&admin, "", json!({ "jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": { "uri": "dumbslab://guide" } }));
    assert!(guide.body["result"]["contents"][0]["text"].as_str().unwrap().contains("edit_post"));
    let post_res = h.mcp(
        &admin,
        "",
        json!({ "jsonrpc": "2.0", "id": 11, "method": "resources/read", "params": { "uri": format!("dumbslab://posts/{pid}") } }),
    );
    assert!(post_res.body["result"]["contents"][0]["text"].as_str().unwrap().contains("title: From an agent"));

    let anon = h.mcp(&Auth::None, "", json!({ "jsonrpc": "2.0", "id": 12, "method": "tools/list" }));
    assert_eq!(anon.status, 401);
    assert!(anon.header("www-authenticate").unwrap().contains("resource_metadata"));
}

fn pkce_pair() -> (String, String) {
    let verifier = "a".repeat(20) + "-verifier-for-dumbslab-tests-0123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn query_of(location: &str) -> std::collections::HashMap<String, String> {
    dumbslab_core::oauth::parse_form(location.split_once('?').map(|(_, q)| q).unwrap_or_default())
}

#[test]
fn oauth_authorization_code_flow() {
    let h = H::new();
    let (cookie, _) = h.setup();
    let meta = h.ok("GET", "/.well-known/oauth-authorization-server", None, &Auth::None);
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    let prm = h.ok("GET", "/.well-known/oauth-protected-resource/mcp", None, &Auth::None);
    assert_eq!(prm["resource"], "https://kb.test/mcp");

    let reg = h.call(
        "POST",
        "/oauth/register",
        Some(json!({ "client_name": "Test Agent", "redirect_uris": ["http://localhost:9999/cb"] })),
        &Auth::None,
    );
    assert_eq!(reg.status, 201);
    let client_id = reg.body["client_id"].as_str().unwrap().to_string();
    let bad_reg = h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": ["http://evil.test/cb"] })), &Auth::None);
    assert_eq!(bad_reg.status, 400);

    let (verifier, challenge) = pkce_pair();
    let q = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state=xyz&scope=read%20write",
        urlencoding::encode("http://localhost:9999/cb")
    );
    // Signed out: sent to the login page with a way back.
    let anon = h.call("GET", &format!("/oauth/authorize?{q}"), None, &Auth::None);
    assert_eq!(anon.status, 302);
    assert!(anon.header("location").unwrap().starts_with("/login?next="));
    // Signed in: consent page with a CSRF token.
    let page = h.call("GET", &format!("/oauth/authorize?{q}"), None, &cookie);
    assert_eq!(page.status, 200);
    let html = page.text();
    assert!(html.contains("Test Agent"));
    let csrf = html.split("name=\"csrf\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();

    // A forged form (wrong CSRF) is refused.
    let forged = h.raw(
        "POST",
        "/oauth/authorize",
        format!("{q}&decision=approve&csrf=bad").into_bytes(),
        "application/x-www-form-urlencoded",
        &cookie,
    );
    assert_eq!(forged.status, 400);
    let approve = h.raw(
        "POST",
        "/oauth/authorize",
        format!("{q}&decision=approve&csrf={csrf}").into_bytes(),
        "application/x-www-form-urlencoded",
        &cookie,
    );
    assert_eq!(approve.status, 302);
    let loc = query_of(approve.header("location").unwrap());
    assert_eq!(loc["state"], "xyz");
    let code = loc["code"].clone();

    let form = |extra: &str| {
        format!(
            "grant_type=authorization_code&code={code}&client_id={client_id}&redirect_uri={}{extra}",
            urlencoding::encode("http://localhost:9999/cb")
        )
    };
    let wrong = h.raw(
        "POST",
        "/oauth/token",
        form("&code_verifier=wrong-verifier-wrong-verifier-wrong-verifier-123").into_bytes(),
        "application/x-www-form-urlencoded",
        &Auth::None,
    );
    assert_eq!(wrong.body["error"], "invalid_grant");
    // The failed attempt burned the code (single use), so get a fresh one.
    let approve = h.raw(
        "POST",
        "/oauth/authorize",
        format!("{q}&decision=approve&csrf={csrf}").into_bytes(),
        "application/x-www-form-urlencoded",
        &cookie,
    );
    let code = query_of(approve.header("location").unwrap())["code"].clone();
    let form = format!(
        "grant_type=authorization_code&code={code}&client_id={client_id}&redirect_uri={}&code_verifier={verifier}",
        urlencoding::encode("http://localhost:9999/cb")
    );
    let tok = h.raw("POST", "/oauth/token", form.clone().into_bytes(), "application/x-www-form-urlencoded", &Auth::None);
    assert_eq!(tok.status, 200, "{}", tok.body);
    let access = tok.body["access_token"].as_str().unwrap().to_string();
    let refresh = tok.body["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(tok.body["scope"], "read write");
    let reuse = h.raw("POST", "/oauth/token", form.into_bytes(), "application/x-www-form-urlencoded", &Auth::None);
    assert_eq!(reuse.body["error"], "invalid_grant");

    let me = h.mcp(
        &Auth::Bearer(access.clone()),
        "",
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "whoami", "arguments": {} } }),
    );
    assert_eq!(me.body["result"]["structuredContent"]["scopes"], json!(["read", "write"]));

    // Connected apps can't mint long-lived personal tokens.
    let minted = h.call("POST", "/api/v1/tokens", Some(json!({ "name": "persist" })), &Auth::Bearer(access.clone()));
    assert_eq!(minted.status, 403);

    // Refresh rotates: the old access and refresh tokens stop working.
    let r2 = h.raw(
        "POST",
        "/oauth/token",
        format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}").into_bytes(),
        "application/x-www-form-urlencoded",
        &Auth::None,
    );
    assert_eq!(r2.status, 200);
    assert_eq!(h.call("GET", "/api/v1/me", None, &Auth::Bearer(access)).status, 401);
    let again = h.raw(
        "POST",
        "/oauth/token",
        format!("grant_type=refresh_token&refresh_token={refresh}").into_bytes(),
        "application/x-www-form-urlencoded",
        &Auth::None,
    );
    assert_eq!(again.body["error"], "invalid_grant");
    let new_access = r2.body["access_token"].as_str().unwrap().to_string();
    assert_eq!(h.call("GET", "/api/v1/me", None, &Auth::Bearer(new_access.clone())).status, 200);
    // Connected apps stay listed (and revocable) after the hourly access token expires (S7).
    h.store
        .with_tx(|db| (db.execute("UPDATE api_tokens SET expires_at = '2000-01-01T00:00:00.000Z' WHERE kind = 'oauth'", &[]), true))
        .unwrap()
        .unwrap();
    let tokens = h.ok("GET", "/api/v1/tokens", None, &cookie);
    let grant =
        tokens["items"].as_array().unwrap().iter().find(|t| t["kind"] == "oauth" && t["revoked"] == false).expect("grant listed").clone();
    h.ok("DELETE", &format!("/api/v1/tokens/{}", grant["id"].as_str().unwrap()), None, &cookie);
    let r3 = h.raw(
        "POST",
        "/oauth/token",
        format!("grant_type=refresh_token&refresh_token={}", r2.body["refresh_token"].as_str().unwrap()).into_bytes(),
        "application/x-www-form-urlencoded",
        &Auth::None,
    );
    assert_eq!(r3.body["error"], "invalid_grant", "revoking the grant ends the refresh token");
    h.raw("POST", "/oauth/revoke", format!("token={new_access}").into_bytes(), "application/x-www-form-urlencoded", &Auth::None);
    assert_eq!(h.call("GET", "/api/v1/me", None, &Auth::Bearer(new_access)).status, 401);

    // Revoking the listed grant after the app refreshed again still disconnects it (B-S4).
    let approve = h.raw(
        "POST",
        "/oauth/authorize",
        format!("{q}&decision=approve&csrf={csrf}").into_bytes(),
        "application/x-www-form-urlencoded",
        &cookie,
    );
    let code = query_of(approve.header("location").unwrap())["code"].clone();
    let exchange = format!(
        "grant_type=authorization_code&code={code}&client_id={client_id}&redirect_uri={}&code_verifier={verifier}",
        urlencoding::encode("http://localhost:9999/cb")
    );
    let fresh = h.raw("POST", "/oauth/token", exchange.into_bytes(), "application/x-www-form-urlencoded", &Auth::None);
    let listed = h.ok("GET", "/api/v1/tokens", None, &cookie)["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["kind"] == "oauth" && t["revoked"] == false)
        .expect("fresh grant listed")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let refresh = |rt: &str| {
        h.raw(
            "POST",
            "/oauth/token",
            format!("grant_type=refresh_token&refresh_token={rt}").into_bytes(),
            "application/x-www-form-urlencoded",
            &Auth::None,
        )
    };
    let rotated = refresh(fresh.body["refresh_token"].as_str().unwrap());
    assert_eq!(rotated.status, 200);
    h.ok("DELETE", &format!("/api/v1/tokens/{listed}"), None, &cookie);
    assert_eq!(h.call("GET", "/api/v1/me", None, &Auth::Bearer(rotated.body["access_token"].as_str().unwrap().to_string())).status, 401);
    assert_eq!(refresh(rotated.body["refresh_token"].as_str().unwrap()).body["error"], "invalid_grant");
}

#[test]
fn webhooks_are_signed() {
    let h = H::new();
    let (_, admin) = h.setup();
    let hook = h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.test/in", "events": ["post.*"] })), &admin);
    let secret = hook["secret"].as_str().unwrap().to_string();
    let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "Hooked", "status": "published" })), &admin);
    assert_eq!(r.status, 200);
    assert_eq!(r.effects.len(), 1);
    let Effect::Webhook(d) = &r.effects[0];
    assert_eq!(d.url, "https://hooks.test/in");
    let header = |n: &str| d.headers.iter().find(|(k, _)| k == n).unwrap().1.clone();
    let expected = dumbslab_core::util::hmac_sha256_hex(&secret, &format!("{}.{}", header("x-dumbslab-timestamp"), d.body));
    assert_eq!(header("x-dumbslab-signature"), format!("sha256={expected}"));
    let payload: Value = serde_json::from_str(&d.body).unwrap();
    assert_eq!(payload["event"], "post.created");
    // Comments don't match `post.*`.
    let c = h.call("POST", &format!("/api/v1/posts/{}/comments", r.body["id"].as_str().unwrap()), Some(json!({ "body": "hi" })), &admin);
    assert!(c.effects.is_empty());
}

#[test]
fn rest_routing_and_docs() {
    let h = H::new();
    let (_, admin) = h.setup();
    let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Routing", "status": "published" })), &admin);
    let id = post["id"].as_str().unwrap();
    // Query strings are coerced to the schema's types.
    let page = h.ok("GET", "/api/v1/posts?limit=1&sort=title", None, &admin);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert!(page["next_cursor"].is_string());
    // DELETE with query parameters.
    h.ok("POST", "/api/v1/reactions", Some(json!({ "target_type": "post", "target_id": id, "emoji": "🎉" })), &admin);
    let removed =
        h.ok("DELETE", &format!("/api/v1/reactions?target_type=post&target_id={id}&emoji={}", urlencoding::encode("🎉")), None, &admin);
    assert!(removed["reactions"].as_array().unwrap().is_empty());
    // The generic operations endpoint.
    let via_ops = h.ok("POST", "/api/v1/operations/get_post", Some(json!({ "id": id })), &admin);
    assert_eq!(via_ops["title"], "Routing");
    assert_eq!(h.call("POST", "/api/v1/operations/nope", Some(json!({})), &admin).status, 404);
    // Unknown fields are rejected so agents learn the right names.
    let typo = h.call("POST", "/api/v1/posts", Some(json!({ "titel": "x" })), &admin);
    assert_eq!(typo.status, 400);
    assert!(typo.body["error"]["message"].as_str().unwrap().contains("titel"));
    assert_eq!(h.call("PUT", "/api/v1/posts", None, &admin).status, 405);
    assert_eq!(h.call("GET", "/api/v1/nope", None, &admin).status, 404);

    let spec = h.ok("GET", "/api/v1/openapi.json", None, &Auth::None);
    assert_eq!(spec["openapi"], "3.1.0");
    assert!(spec["paths"]["/api/v1/posts/{id}"]["patch"]["requestBody"].is_object());
    let llms = h.call("GET", "/llms.txt", None, &Auth::None);
    assert!(llms.text().contains("https://kb.test/mcp"));
}
