//! End-to-end tests through the real request path (routing, auth, transactions, SQLite).

use base64::Engine;
use dumbslab::store::Store;
use dumbslab_core::db::DbExt;
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
    /// The raw response body (for files).
    bytes: Vec<u8>,
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
            cfg: HostConfig { base_url: Some("https://kb.test".into()), setup_token: Some("SETUP".into()), ..Default::default() },
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
        self.send(&req)
    }

    /// Runs a request built by the test (for a custom origin or client address).
    fn send(&self, req: &Request) -> Res {
        let out = self
            .store
            .with_tx(|db| {
                let o = dumbslab_core::handle(db, &self.cfg, req).expect("core route");
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
        Res { status: out.response.status, body, bytes: out.response.body, headers: out.response.headers, effects: out.effects }
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
    // Oversized login input is refused up front, and throttle keys are fixed-size hashes.
    let huge = format!("{}@acme.test", "a".repeat(300));
    assert_eq!(h.call("POST", "/api/v1/auth/login", Some(json!({ "email": huge, "password": "nopenope" })), &Auth::None).status, 400);
    let longest_key =
        h.store.with_tx(|db| (db.scalar_i64("SELECT COALESCE(MAX(length(key)), 0) FROM login_attempts", &[]), true)).unwrap().unwrap();
    assert!(longest_key <= 70, "throttle keys stay small: {longest_key}");
    // Failed-login bookkeeping is forgotten once its window closes (anyone can fail with any email).
    h.store.with_tx(|db| (db.execute("UPDATE login_attempts SET window_start = '2000-01-01T00:00:00.000Z'", &[]), true)).unwrap().unwrap();
    h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "someone-else@acme.test", "password": "nopenope" })), &Auth::None);
    let kept = h.store.with_tx(|db| (db.scalar_i64("SELECT COUNT(*) FROM login_attempts", &[]), true)).unwrap().unwrap();
    assert_eq!(kept, 2, "only the current window's records remain: that email's and the workspace's");

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
    // Registration is anonymous, so it is bounded: few, short redirect URIs, and stale clients pruned.
    let many: Vec<String> = (0..6).map(|i| format!("http://localhost:{}/cb", 9000 + i)).collect();
    assert_eq!(h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": many })), &Auth::None).status, 400);
    let long = format!("http://localhost:9000/{}", "a".repeat(600));
    assert_eq!(h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": [long] })), &Auth::None).status, 400);
    let stale = h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": ["http://localhost:9998/cb"] })), &Auth::None);
    let stale_id = stale.body["client_id"].as_str().unwrap().to_string();
    h.store
        .with_tx(|db| {
            (
                db.execute(
                    "UPDATE oauth_clients SET created_at = '2000-01-01T00:00:00.000Z' WHERE client_id = ?",
                    &[stale_id.clone().into()],
                ),
                true,
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": ["http://localhost:9997/cb"] })), &Auth::None).status, 201);
    let left = h
        .store
        .with_tx(|db| (db.scalar_i64("SELECT COUNT(*) FROM oauth_clients WHERE client_id = ?", &[stale_id.clone().into()]), true))
        .unwrap()
        .unwrap();
    assert_eq!(left, 0, "never-used old client pruned");

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
    // At the cap, the oldest never-used client makes room instead of locking everyone out;
    // clients that connected, or whose consent page someone opened, are never evicted.
    let pending = h.call(
        "POST",
        "/oauth/register",
        Some(json!({ "client_name": "Pending", "redirect_uris": ["http://localhost:9995/cb"] })),
        &Auth::None,
    );
    let pending_id = pending.body["client_id"].as_str().unwrap().to_string();
    let pending_q = format!(
        "response_type=code&client_id={pending_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state=p",
        urlencoding::encode("http://localhost:9995/cb")
    );
    assert_eq!(h.call("GET", &format!("/oauth/authorize?{pending_q}"), None, &cookie).status, 200);
    h.store
        .with_tx(|db| {
            let mut r = Ok(0);
            for i in 0..dumbslab_core::oauth::MAX_CLIENTS {
                r = db.execute(
                    "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, created_at) VALUES (?, 'flood', '[]', ?)",
                    &[format!("flood{i}").into(), chrono::Utc::now().to_rfc3339().into()],
                );
            }
            (r, true)
        })
        .unwrap()
        .unwrap();
    assert_eq!(h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": ["http://localhost:9996/cb"] })), &Auth::None).status, 201);
    assert_eq!(h.call("GET", &format!("/oauth/authorize?{q}"), None, &cookie).status, 200, "the connected client survived");
    assert_eq!(h.call("GET", &format!("/oauth/authorize?{pending_q}"), None, &cookie).status, 200, "the client awaiting consent survived");
    // The protection expires: an abandoned consent page doesn't pin its client for good.
    h.store
        .with_tx(|db| {
            (
                db.execute(
                    "UPDATE oauth_clients SET seen_at = '2000-01-01T00:00:00.000Z' WHERE client_id = ?",
                    &[pending_id.clone().into()],
                ),
                true,
            )
        })
        .unwrap()
        .unwrap();
    h.store
        .with_tx(|db| {
            (
                db.execute(
                    "UPDATE oauth_clients SET created_at = '1999-01-01T00:00:00.000Z' WHERE client_id = ?",
                    &[pending_id.clone().into()],
                ),
                true,
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(h.call("POST", "/oauth/register", Some(json!({ "redirect_uris": ["http://localhost:9994/cb"] })), &Auth::None).status, 201);
    let pending_left = h
        .store
        .with_tx(|db| (db.scalar_i64("SELECT COUNT(*) FROM oauth_clients WHERE client_id = ?", &[pending_id.clone().into()]), true))
        .unwrap()
        .unwrap();
    assert_eq!(pending_left, 0, "an abandoned client is evicted once its protection expired");
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
    let Effect::Webhook(d) = &r.effects[0] else { panic!("expected a webhook delivery") };
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
    let robots = h.call("GET", "/robots.txt", None, &Auth::None);
    assert_eq!((robots.status, robots.text().as_str()), (200, "User-agent: *\nDisallow: /\n"), "workspaces keep crawlers out");
}

#[test]
fn signed_signup_links_set_up_hosted_workspaces() {
    use dumbslab_core::tenancy::signup_token;
    let mut h = H::new();
    h.cfg = HostConfig {
        base_url: Some("https://acme.kb.test".into()),
        signup_secret: Some("sekret".into()),
        workspace: Some("acme".into()),
        ..Default::default()
    };
    let now = chrono::Utc::now().timestamp();
    let setup = |token: &str| {
        h.call(
            "POST",
            "/api/v1/auth/setup",
            Some(json!({ "setup_token": token, "workspace_name": "Acme", "name": "Ada", "email": "ada@acme.test", "password": "password123" })),
            &Auth::None,
        )
    };
    assert_eq!(setup(&signup_token("sekret", "other", now + 3600)).status, 403, "link for another workspace");
    assert_eq!(setup(&signup_token("sekret", "acme", now - 1)).status, 403, "expired link");
    assert_eq!(setup(&signup_token("wrong", "acme", now + 3600)).status, 403, "wrong secret");
    assert_eq!(setup("").status, 403);
    let ok = setup(&signup_token("sekret", "acme", now + 3600));
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(setup(&signup_token("sekret", "acme", now + 3600)).status, 409, "only once");
}

/// A free-plan budget no test reaches.
const ROOMY: dumbslab_core::tenancy::FreeBudget = dumbslab_core::tenancy::FreeBudget { writes_per_day: u64::MAX, storage_bytes: u64::MAX };

#[test]
fn directory_reserves_addresses_within_limits() {
    use chrono::{Duration, Utc};
    use dumbslab_core::tenancy::{self, Limits};
    let h = H::new();
    let limits = Limits { per_ip_per_day: 2, per_day: 4, max_workspaces: 5, free: ROOMY };
    let t0 = Utc::now();
    let t1 = t0 + Duration::days(2);
    let run = |f: &dyn Fn(&dyn dumbslab_core::Db) -> dumbslab_core::ApiResult<()>| {
        h.store
            .with_tx(|db| {
                let r = f(db);
                let ok = r.is_ok();
                (r, ok)
            })
            .unwrap()
    };
    let reserve = |slug: &'static str, ip: &'static str, at| run(&move |db| tenancy::reserve(db, slug, "Name", ip, at, limits).map(|_| ()));
    let status = |r: dumbslab_core::ApiResult<()>| r.err().map(|e| e.status);
    run(&|db| tenancy::directory_migrate(db)).unwrap();
    let unavailable = |slug: &'static str, at| h.store.with_tx(|db| (tenancy::address_unavailable(db, slug, at), true)).unwrap().unwrap();

    // Taken while reserved, and once active. A sign-up link names exactly one live reservation.
    assert_eq!(unavailable("acme", t0), None);
    assert_eq!(status(reserve("acme", "ip1", t0)), None);
    assert_eq!(unavailable("acme", t0).as_deref(), Some("acme is taken; pick another address"));
    let matches = |slug: &'static str, expires: i64, at| {
        h.store.with_tx(|db| (tenancy::reservation_matches(db, slug, expires, at), true)).unwrap().unwrap()
    };
    let expires = t0.timestamp() + tenancy::RESERVATION_MINUTES * 60;
    assert!(matches("acme", expires, t0));
    assert!(!matches("acme", expires + 1, t0), "another reservation's link");
    assert!(!matches("acme", expires, t0 + Duration::minutes(61)), "expired");
    assert_eq!(status(reserve("acme", "ip2", t0)), Some(409));
    run(&|db| tenancy::activate(db, "acme", t0)).unwrap();
    assert!(!matches("acme", expires, t0), "used links stop working");
    assert_eq!(status(reserve("acme", "ip2", t0 + Duration::hours(3))), Some(409));
    // Per-IP, then per-day limits.
    assert_eq!(status(reserve("beta", "ip1", t0)), None);
    assert_eq!(status(reserve("gamma", "ip1", t0)), Some(429));
    assert_eq!(status(reserve("delta", "ip9", t0)), None);
    assert_eq!(status(reserve("eps", "ip10", t0)), None);
    run(&|db| tenancy::activate(db, "delta", t0)).unwrap();
    run(&|db| tenancy::activate(db, "eps", t0)).unwrap();
    assert_eq!(status(reserve("zeta", "ip11", t0)), Some(429));
    // Two days later: beta's abandoned reservation is free again, then the total cap applies.
    assert!(unavailable("beta", t0).is_some());
    assert_eq!(unavailable("beta", t1), None);
    assert!(unavailable("acme", t1).is_some(), "active workspaces stay taken");
    assert!(unavailable("www", t1).unwrap().contains("reserved"));
    assert_eq!(status(reserve("beta", "ip3", t1)), None);
    assert_eq!(status(reserve("eta", "ip4", t1)), None);
    assert_eq!(status(reserve("theta", "ip5", t1)), Some(503));
    // Operator actions and reserved names.
    run(&|db| tenancy::set_status(db, "acme", "disabled")).unwrap();
    run(&|db| tenancy::remove(db, "eps")).unwrap();
    // Disabled or deleted reservations reject their links.
    let eta_expires = t1.timestamp() + tenancy::RESERVATION_MINUTES * 60;
    assert!(matches("eta", eta_expires, t1));
    run(&|db| tenancy::set_status(db, "eta", "disabled")).unwrap();
    assert!(!matches("eta", eta_expires, t1));
    run(&|db| tenancy::remove(db, "eta")).unwrap();
    assert!(!matches("eta", eta_expires, t1));
    let entries = h.store.with_tx(|db| (tenancy::list(db), true)).unwrap().unwrap();
    assert!(entries.iter().any(|e| e.slug == "acme" && e.status == "disabled"));
    assert!(!entries.iter().any(|e| e.slug == "eps"));
    assert_eq!(status(reserve("www", "ip8", t1)), Some(400));
}

#[test]
fn hosted_workspaces_change_address() {
    use dumbslab_core::tenancy::{self, signup_token};
    // A self-hosted server has no address to change.
    let plain = H::new();
    let (_, plain_admin) = plain.setup();
    let r = plain.call("POST", "/api/v1/settings/address", Some(json!({ "address": "wiki" })), &plain_admin);
    assert_eq!(r.status, 400, "{}", r.body);
    assert!(plain.ok("GET", "/api/v1/settings", None, &plain_admin)["address"].is_null());

    let mut h = H::new();
    h.cfg = HostConfig {
        base_url: Some("https://acme.kb.test".into()),
        signup_secret: Some("sekret".into()),
        workspace: Some("acme".into()),
        ..Default::default()
    };
    let token = signup_token("sekret", "acme", chrono::Utc::now().timestamp() + 3600);
    let r = h.call(
        "POST",
        "/api/v1/auth/setup",
        Some(json!({ "setup_token": token, "workspace_name": "Acme", "name": "Ada", "email": "ada@acme.test", "password": "password123" })),
        &Auth::None,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let admin = session_from(&r);
    assert_eq!(h.ok("GET", "/api/v1/settings", None, &admin)["address"], "acme");
    let (_, member) = h.user(&admin, "mo@acme.test", "Mo", "member");
    let change = |to: &str, auth: &Auth| h.call("POST", "/api/v1/settings/address", Some(json!({ "address": to })), auth);
    assert_eq!(change("wiki", &member).status, 403, "admins only");
    assert_eq!(change("not valid", &admin).status, 400);
    assert_eq!(change("www", &admin).status, 400, "reserved");
    assert_eq!(change("acme", &admin).status, 409, "already there");

    // The operation asks the host to move; nothing changes until the host has claimed the address.
    let r = change(" Wiki ", &admin);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["url"], "https://wiki.kb.test");
    assert_eq!(r.body["mcp_url"], "https://wiki.kb.test/mcp");
    assert_eq!(r.body["previous_address"], "acme");
    let mv = r
        .effects
        .iter()
        .find_map(|e| match e {
            Effect::MoveAddress(m) => Some(m.clone()),
            _ => None,
        })
        .expect("a move");
    assert_eq!((mv.from.as_str(), mv.to.as_str()), ("acme", "wiki"));
    let moved_to = |h: &H| h.store.with_tx(|db| (tenancy::moved_to(db), true)).unwrap().unwrap();
    assert_eq!(moved_to(&h), None);
    let has_event = |h: &H| {
        h.ok("GET", "/api/v1/activity", None, &member)["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["event"] == "workspace.address_changed")
    };
    assert!(!has_event(&h));

    let effects = h
        .store
        .with_tx(|db| {
            let r = tenancy::finish_move(db, &h.cfg, &mv, "https://wiki.kb.test");
            let ok = r.is_ok();
            (r, ok)
        })
        .unwrap()
        .unwrap();
    assert!(effects.is_empty(), "no webhooks to deliver");
    assert_eq!(moved_to(&h).as_deref(), Some("wiki"));
    assert!(has_event(&h), "everyone sees the move");
}

#[test]
fn directory_moves_addresses() {
    use chrono::{Duration, Utc};
    use dumbslab_core::tenancy::{self, Limits};
    let h = H::new();
    let limits = Limits { per_ip_per_day: 50, per_day: 50, max_workspaces: 50, free: ROOMY };
    let t0 = Utc::now();
    let run = |f: &dyn Fn(&dyn dumbslab_core::Db) -> dumbslab_core::ApiResult<()>| {
        h.store
            .with_tx(|db| {
                let r = f(db);
                let ok = r.is_ok();
                (r, ok)
            })
            .unwrap()
    };
    let status = |r: dumbslab_core::ApiResult<()>| r.err().map(|e| e.status);
    let reserve = |slug: &'static str, at| run(&move |db| tenancy::reserve(db, slug, "Name", "ip", at, limits).map(|_| ()));
    let mv = |home: &'static str, to: &'static str, at| run(&move |db| tenancy::move_address(db, home, to, at));
    let resolve = |slug: &str| h.store.with_tx(|db| (tenancy::resolve(db, slug), true)).unwrap().unwrap();
    let entry = |slug: &str| {
        let list = h.store.with_tx(|db| (tenancy::list(db), true)).unwrap().unwrap();
        let e = list.into_iter().find(|e| e.slug == slug).unwrap();
        (e.address, e.previous_addresses)
    };
    let owned = |home: &str, moved: &[&str]| Some((home.to_string(), moved.iter().map(|s| s.to_string()).collect::<Vec<_>>()));
    run(&|db| tenancy::directory_migrate(db)).unwrap();
    for slug in ["acme", "beta"] {
        reserve(slug, t0).unwrap();
        run(&move |db| tenancy::activate(db, slug, t0)).unwrap();
    }
    reserve("held", t0).unwrap();
    reserve("stale", t0).unwrap();

    assert_eq!(status(mv("acme", "beta", t0)), Some(409), "another workspace");
    assert_eq!(status(mv("acme", "held", t0)), Some(409), "a live reservation");
    assert_eq!(status(mv("held", "zeta", t0)), Some(403), "not set up yet");
    assert_eq!(status(mv("nope", "zeta", t0)), Some(404));
    assert_eq!(status(mv("acme", "www", t0)), Some(400));
    assert_eq!(status(mv("acme", "wiki", t0)), None);
    // Both addresses now belong to acme, for good.
    let unavailable = |slug: &'static str| h.store.with_tx(|db| (tenancy::address_unavailable(db, slug, t0), true)).unwrap().unwrap();
    assert!(unavailable("wiki").is_some(), "the sign-up form calls a moved-to address taken");
    assert_eq!(status(reserve("wiki", t0)), Some(409));
    assert_eq!(status(reserve("acme", t0 + Duration::days(3))), Some(409));
    assert_eq!(status(mv("beta", "wiki", t0)), Some(409));
    assert_eq!(resolve("wiki"), owned("acme", &["wiki"]));
    assert_eq!(resolve("acme"), owned("acme", &["wiki"]));
    assert_eq!(resolve("nobody"), None);
    assert_eq!(entry("acme"), ("wiki".to_string(), vec!["acme".to_string()]));
    // Moving back doesn't use up another address.
    assert_eq!(status(mv("acme", "acme", t0)), None);
    assert_eq!(entry("acme"), ("acme".to_string(), vec!["wiki".to_string()]));
    assert_eq!(status(mv("acme", "wiki", t0)), None);
    // A lapsed reservation still blocks moves (its sign-up may be finishing), but not sign-ups.
    assert_eq!(status(mv("acme", "stale", t0 + Duration::hours(2))), Some(409));
    assert_eq!(status(reserve("stale", t0 + Duration::hours(2))), None);
    // Five addresses at most, counting the first; earlier ones keep working at the cap.
    assert_eq!(status(mv("acme", "three", t0)), None);
    assert_eq!(resolve("three"), owned("acme", &["wiki", "three"]));
    assert_eq!(status(mv("acme", "four", t0)), None);
    assert_eq!(status(mv("acme", "five", t0)), None);
    assert_eq!(status(mv("acme", "six", t0)), Some(409));
    assert_eq!(status(mv("acme", "wiki", t0)), None);
    // Disabled workspaces can't move, and removing one frees all its addresses.
    run(&|db| tenancy::set_status(db, "acme", "disabled")).unwrap();
    assert_eq!(status(mv("acme", "four", t0)), Some(403));
    run(&|db| tenancy::remove(db, "acme")).unwrap();
    assert_eq!(resolve("wiki"), None);
    assert_eq!(status(reserve("wiki", t0)), None);
}

// ---------------------------------------------------------------------------
// Security review regressions (October 2026).

fn count(h: &H, sql: &str) -> i64 {
    h.store.with_tx(|db| (db.scalar_i64(sql, &[]), true)).unwrap().unwrap()
}

fn register_app(h: &H) -> String {
    let reg = h.call(
        "POST",
        "/oauth/register",
        Some(json!({ "client_name": "Some App", "redirect_uris": ["http://localhost:9999/cb"] })),
        &Auth::None,
    );
    assert_eq!(reg.status, 201, "{}", reg.body);
    reg.body["client_id"].as_str().unwrap().to_string()
}

/// The authorization request for `client_id`, plus `extra` query parameters (`&scope=…`, `&resource=…`).
fn authorize_query(client_id: &str, extra: &str) -> String {
    let (_, challenge) = pkce_pair();
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state=s{extra}",
        urlencoding::encode("http://localhost:9999/cb")
    )
}

/// Approves the consent page as `cookie` and returns the authorization code.
fn approve(h: &H, cookie: &Auth, q: &str) -> String {
    let page = h.call("GET", &format!("/oauth/authorize?{q}"), None, cookie);
    assert_eq!(page.status, 200, "consent page: {}", page.text());
    let csrf = page.text().split("name=\"csrf\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let approved = h.raw(
        "POST",
        "/oauth/authorize",
        format!("{q}&decision=approve&csrf={csrf}").into_bytes(),
        "application/x-www-form-urlencoded",
        cookie,
    );
    assert_eq!(approved.status, 302);
    query_of(approved.header("location").unwrap())["code"].clone()
}

fn exchange(h: &H, client_id: &str, code: &str, extra: &str) -> Res {
    let (verifier, _) = pkce_pair();
    let form = format!(
        "grant_type=authorization_code&code={code}&client_id={client_id}&redirect_uri={}&code_verifier={verifier}{extra}",
        urlencoding::encode("http://localhost:9999/cb")
    );
    h.raw("POST", "/oauth/token", form.into_bytes(), "application/x-www-form-urlencoded", &Auth::None)
}

/// Connects a new app for the person signed in with `cookie` and returns the token response.
fn connect_app(h: &H, cookie: &Auth, extra: &str) -> Res {
    let client_id = register_app(h);
    let code = approve(h, cookie, &authorize_query(&client_id, extra));
    let tok = exchange(h, &client_id, &code, "");
    assert_eq!(tok.status, 200, "{}", tok.body);
    tok
}

fn sign_in(h: &H, email: &str, password: &str) -> Auth {
    let r = h.call("POST", "/api/v1/auth/login", Some(json!({ "email": email, "password": password })), &Auth::None);
    assert_eq!(r.status, 200, "{}", r.body);
    session_from(&r)
}

#[test]
fn trashed_posts_are_private_to_their_author_and_admins() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, author) = h.user(&admin, "ana@acme.test", "Ana Author", "member");
    let (_, member) = h.user(&admin, "mo@acme.test", "Mo Member", "member");
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");
    let post = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Retired runbook", "content": "the old root password was hunter2", "status": "published" })),
        &author,
    );
    let id = post["id"].as_str().unwrap().to_string();
    h.ok("DELETE", &format!("/api/v1/posts/{id}"), None, &admin);

    // Everyone else loses the post: reads, the trash list, its history, activity and restore.
    for who in [&viewer, &member] {
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, who).status, 404, "a trashed post is readable");
        assert!(!ids(&h.ok("GET", "/api/v1/posts?status=trash", None, who)).contains(&id));
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}/versions/1"), None, who).status, 404);
        let feed = h.ok("GET", "/api/v1/activity?limit=200", None, who);
        assert!(feed["items"].as_array().unwrap().iter().all(|a| a["post_id"] != json!(id)), "trashed post in activity");
    }
    assert_eq!(h.call("POST", &format!("/api/v1/posts/{id}/restore"), None, &member).status, 404, "an unrelated member restored it");

    // Its author and admins still see it and can restore it.
    assert!(h.ok("GET", &format!("/api/v1/posts/{id}"), None, &admin)["deleted_at"].is_string());
    assert!(ids(&h.ok("GET", "/api/v1/posts?status=trash", None, &author)).contains(&id));
    h.ok("POST", &format!("/api/v1/posts/{id}/restore"), None, &author);
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &viewer).status, 200);
}

#[test]
fn topic_changes_never_widen_a_private_post() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, member) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");
    let private =
        h.ok("POST", "/api/v1/topics", Some(json!({ "name": "HR", "visibility": "private", "members": ["mia@acme.test"] })), &admin);
    let tid = private["id"].as_str().unwrap().to_string();
    let post = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Layoff plan", "content": "confidential", "topic_ids": [tid], "status": "published" })),
        &admin,
    );
    let id = post["id"].as_str().unwrap().to_string();
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &viewer).status, 404);

    // Removing its last private topic would publish it to everyone, however it's asked for.
    for change in [json!({ "topic_ids": [] }), json!({ "remove_topic_ids": [tid] })] {
        let r = h.call("PATCH", &format!("/api/v1/posts/{id}"), Some(change), &member);
        assert_eq!(r.status, 409, "{}", r.body);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &viewer).status, 404, "the private post was exposed");
    }

    // Sharing it is an explicit step: add an org-wide topic. Then the private one can go.
    let everyone = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Everyone" })), &admin)["id"].as_str().unwrap().to_string();
    h.ok("PATCH", &format!("/api/v1/posts/{id}"), Some(json!({ "add_topic_ids": [everyone] })), &member);
    h.ok("PATCH", &format!("/api/v1/posts/{id}"), Some(json!({ "remove_topic_ids": [tid] })), &member);
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &viewer).status, 200);
}

#[test]
fn deleted_comments_leave_no_body_behind() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");
    h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.test/in", "events": ["comment.*"] })), &admin);
    let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Office", "status": "published" })), &admin);
    let pid = post["id"].as_str().unwrap().to_string();

    let created = h.call("POST", &format!("/api/v1/posts/{pid}/comments"), Some(json!({ "body": "the door code is 4512" })), &viewer);
    assert_eq!(created.status, 200);
    let cid = created.body["id"].as_str().unwrap().to_string();
    let feed = |who: &Auth| h.ok("GET", &format!("/api/v1/activity?post_id={pid}&limit=200"), None, who).to_string();
    assert!(!feed(&viewer).contains("4512"), "the comment body is stored in activity");
    // Webhooks still receive the body when the comment is written.
    let Effect::Webhook(d) = &created.effects[0] else { panic!("expected a webhook delivery") };
    assert!(d.body.contains("4512"));

    h.ok("PATCH", &format!("/api/v1/comments/{cid}"), Some(json!({ "body": "the door code is 7788" })), &viewer);
    assert!(!feed(&viewer).contains("7788"));
    h.ok("DELETE", &format!("/api/v1/comments/{cid}"), None, &viewer);
    let kept = h
        .store
        .with_tx(|db| (db.one("SELECT body, quote FROM comments WHERE id = ?", &[cid.clone().into()]), true))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(kept.str("body"), "", "a deleted comment keeps its body");

    // Bodies recorded before this fix are scrubbed by a migration, even after the post is purged.
    h.store
        .with_tx(|db| {
            let r = db.execute(
                "INSERT INTO activity (event, actor_id, via, target_type, target_id, post_id, summary, data, created_at)
                 VALUES ('comment.created', NULL, 'web', 'comment', 'old', ?, 'commented', '{\"body\":\"legacy 9999\"}', '2026-10-01T00:00:00.000Z')",
                &[pid.clone().into()],
            );
            (r, true)
        })
        .unwrap()
        .unwrap();
    h.ok("DELETE", &format!("/api/v1/posts/{pid}?permanent=true"), None, &admin);
    // Run the scrub (0004) again, and the migrations after it.
    let before_scrub = dumbslab_core::db::MIGRATIONS.iter().position(|m| m.contains("UPDATE activity SET data = '{}'")).unwrap();
    h.store
        .with_tx(|db| (db.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", &[before_scrub.to_string().into()]), true))
        .unwrap()
        .unwrap();
    let _reopened = Store::open(&h._dir.path().join("t.db")).unwrap();
    assert!(!h.ok("GET", "/api/v1/activity?limit=200", None, &admin).to_string().contains("9999"));
}

#[test]
fn connected_apps_cannot_manage_credentials() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, pat) = h.user(&admin, "mia@acme.test", "Mia", "member");
    let mia = sign_in(&h, "mia@acme.test", "password123");
    let app = connect_app(&h, &mia, "&scope=read%20write");
    let app_token = Auth::Bearer(app.body["access_token"].as_str().unwrap().to_string());
    let tokens = h.ok("GET", "/api/v1/tokens", None, &mia);
    let id_of =
        |kind: &str| tokens["items"].as_array().unwrap().iter().find(|t| t["kind"] == kind).unwrap()["id"].as_str().unwrap().to_string();

    // A write grant can't revoke the person's other credentials.
    assert_eq!(h.call("DELETE", &format!("/api/v1/tokens/{}", id_of("personal")), None, &app_token).status, 403);
    assert_eq!(h.call("GET", "/api/v1/me", None, &pat).status, 200);

    // Tokens can't guess (or change) the password; the browser can, within sign-in limits.
    let change = |pw: &str, who: &Auth| {
        h.call("POST", "/api/v1/me/password", Some(json!({ "current_password": pw, "new_password": "brand-new-pass" })), who).status
    };
    assert_eq!(change("guess-number-1", &app_token), 403);
    assert_eq!(change("password123", &pat), 403);
    for i in 0..10 {
        assert_eq!(change(&format!("wrong-guess-{i}"), &mia), 403);
    }
    assert_eq!(change("password123", &mia), 429, "current-password guesses aren't throttled");

    // An app can still disconnect itself.
    h.ok("DELETE", &format!("/api/v1/tokens/{}", id_of("oauth")), None, &app_token);
    assert_eq!(h.call("GET", "/api/v1/me", None, &app_token).status, 401);
}

#[test]
fn sign_in_limits_cover_every_email() {
    let mut h = H::new();
    h.setup();
    let login = |h: &H, email: &str, ip: &str, origin: &str| {
        h.send(&Request {
            method: "POST".into(),
            path: "/api/v1/auth/login".into(),
            headers: vec![("content-type".into(), "application/json".into()), ("x-dumbslab-client".into(), "web".into())],
            body: serde_json::to_vec(&json!({ "email": email, "password": "not-the-password" })).unwrap(),
            origin: origin.into(),
            client_ip: Some(ip.into()),
            ..Default::default()
        })
    };
    // A failure counts against the email, the client's address and the whole workspace.
    assert_eq!(login(&h, "first@acme.test", "203.0.113.7", "https://kb.test").status, 401);
    assert_eq!(count(&h, "SELECT COUNT(*) FROM login_attempts"), 3, "only the email is throttled");

    // An address that failed many times with other emails is stopped before any password check.
    h.store.with_tx(|db| (db.execute("UPDATE login_attempts SET failures = 1000 WHERE key LIKE 'ip:%'", &[]), true)).unwrap().unwrap();
    assert_eq!(login(&h, "fresh@acme.test", "203.0.113.7", "https://kb.test").status, 429);
    assert_eq!(login(&h, "fresh@acme.test", "198.51.100.9", "https://kb.test").status, 401);
    // So is everyone, once the workspace as a whole has failed too often (addresses are cheap).
    h.store.with_tx(|db| (db.execute("UPDATE login_attempts SET failures = 1000 WHERE key = 'workspace'", &[]), true)).unwrap().unwrap();
    assert_eq!(login(&h, "other@acme.test", "192.0.2.1", "https://kb.test").status, 429);
    h.store.with_tx(|db| (db.execute("DELETE FROM login_attempts", &[]), true)).unwrap().unwrap();

    // Behind a proxy that doesn't forward the scheme, an HTTPS public URL still gets Secure cookies.
    h.cfg.base_url = Some("https://kb.test".into());
    let ok = h.send(&Request {
        method: "POST".into(),
        path: "/api/v1/auth/login".into(),
        headers: vec![("content-type".into(), "application/json".into()), ("x-dumbslab-client".into(), "web".into())],
        body: serde_json::to_vec(&json!({ "email": "ada@acme.test", "password": "correct horse" })).unwrap(),
        origin: "http://kb.test".into(),
        ..Default::default()
    });
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert!(ok.header("set-cookie").unwrap().contains("Secure"), "{:?}", ok.header("set-cookie"));
}

#[test]
fn oauth_tokens_are_bound_to_this_server() {
    let mut h = H::new();
    let (cookie, admin_pat) = h.setup();
    let client_id = register_app(&h);
    let enc = |s: &str| urlencoding::encode(s).into_owned();

    // The authorization server only issues tokens for itself.
    let foreign = h.call(
        "GET",
        &format!("/oauth/authorize?{}", authorize_query(&client_id, &format!("&resource={}", enc("https://evil.test/mcp")))),
        None,
        &cookie,
    );
    assert_eq!(foreign.status, 302, "a token for another resource was offered: {}", foreign.status);
    assert_eq!(query_of(foreign.header("location").unwrap())["error"], "invalid_target");

    // A token for this server can't be redirected elsewhere at the token endpoint either.
    let q = authorize_query(&client_id, &format!("&resource={}", enc("https://kb.test/mcp")));
    let code = approve(&h, &cookie, &q);
    assert_eq!(exchange(&h, &client_id, &code, &format!("&resource={}", enc("https://evil.test/mcp"))).body["error"], "invalid_target");
    let code = approve(&h, &cookie, &q);
    let tok = exchange(&h, &client_id, &code, &format!("&resource={}", enc("https://kb.test/mcp")));
    assert_eq!(tok.status, 200, "{}", tok.body);
    let access = Auth::Bearer(tok.body["access_token"].as_str().unwrap().to_string());
    assert_eq!(h.call("GET", "/api/v1/me", None, &access).status, 200);

    // Presented anywhere else, it's refused. Personal tokens aren't bound to an address.
    h.cfg.base_url = Some("https://other.test".into());
    assert_eq!(h.call("GET", "/api/v1/me", None, &access).status, 401);
    assert_eq!(h.call("GET", "/api/v1/me", None, &admin_pat).status, 200);
}

#[test]
fn read_only_mcp_url_grants_read_only_access() {
    let h = H::new();
    let (cookie, _) = h.setup();
    let list = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let anon = h.mcp(&Auth::None, "read", list.clone());
    assert_eq!(anon.status, 401);
    let challenge = anon.header("www-authenticate").unwrap().to_string();
    assert!(challenge.contains("toolset=read") && challenge.contains("scope=\"read\""), "{challenge}");
    let prm = h.ok("GET", "/.well-known/oauth-protected-resource/mcp?toolset=read", None, &Auth::None);
    assert_eq!(prm["resource"], "https://kb.test/mcp?toolset=read");
    assert_eq!(prm["scopes_supported"], json!(["read"]));

    // Even when the app asks for more, a grant for the read-only URL can only read, wherever it's used.
    let tok =
        connect_app(&h, &cookie, &format!("&scope=read%20write&resource={}", urlencoding::encode("https://kb.test/mcp?toolset=read")));
    assert_eq!(tok.body["scope"], "read");
    let access = Auth::Bearer(tok.body["access_token"].as_str().unwrap().to_string());
    let write = h.mcp(
        &access,
        "",
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "create_post", "arguments": { "title": "Sneaky" } } }),
    );
    assert_eq!(write.body["result"]["isError"], true, "{}", write.body);
    assert_eq!(h.call("POST", "/api/v1/posts", Some(json!({ "title": "Sneaky" })), &access).status, 403);
}

#[test]
fn token_writes_stay_bounded() {
    let h = H::new();
    let (cookie, _) = h.setup();
    let client_id = register_app(&h);
    let tok = exchange(&h, &client_id, &approve(&h, &cookie, &authorize_query(&client_id, "")), "");
    let rows = |h: &H| (count(h, "SELECT COUNT(*) FROM api_tokens"), count(h, "SELECT COUNT(*) FROM oauth_refresh_tokens"));
    let before = rows(&h);
    let mut refresh = tok.body["refresh_token"].as_str().unwrap().to_string();
    for _ in 0..5 {
        let r = h.raw(
            "POST",
            "/oauth/token",
            format!("grant_type=refresh_token&refresh_token={refresh}").into_bytes(),
            "application/x-www-form-urlencoded",
            &Auth::None,
        );
        assert_eq!(r.status, 200, "{}", r.body);
        refresh = r.body["refresh_token"].as_str().unwrap().to_string();
    }
    assert_eq!(rows(&h), before, "refreshing grows storage");

    // Reconnecting the same app replaces its older grants beyond a few.
    for _ in 0..8 {
        let r = exchange(&h, &client_id, &approve(&h, &cookie, &authorize_query(&client_id, "")), "");
        assert_eq!(r.status, 200);
    }
    assert!(count(&h, "SELECT COUNT(*) FROM oauth_refresh_tokens") <= 5);
    assert!(count(&h, "SELECT COUNT(*) FROM api_tokens WHERE kind = 'oauth'") <= 5);

    // Pending authorization codes and sessions per person are capped too.
    let q = authorize_query(&client_id, "");
    for _ in 0..30 {
        approve(&h, &cookie, &q);
    }
    assert!(count(&h, "SELECT COUNT(*) FROM oauth_codes") <= 10);
    let uid = h.ok("GET", "/api/v1/me", None, &cookie)["user"]["id"].as_str().unwrap().to_string();
    h.store
        .with_tx(|db| {
            let mut r = Ok(String::new());
            for _ in 0..80 {
                r = dumbslab_core::auth::create_session(db, &uid, None, chrono::Utc::now());
            }
            (r, true)
        })
        .unwrap()
        .unwrap();
    assert!(count(&h, "SELECT COUNT(*) FROM sessions") <= 50);
}

#[cfg(unix)]
#[test]
fn database_files_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let fresh = dir.path().join("fresh.db");
    let store = Store::open(&fresh).unwrap();
    store.with_tx(|db| (db.execute("INSERT INTO meta (key, value) VALUES ('probe', '1')", &[]), true)).unwrap().unwrap();
    assert_eq!(mode(&fresh), 0o600, "a new database is readable by others");
    let wal = dir.path().join("fresh.db-wal");
    if wal.exists() {
        assert_eq!(mode(&wal), 0o600);
    }
    // Existing installations are tightened.
    let old = dir.path().join("old.db");
    std::fs::write(&old, b"").unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = Store::open(&old).unwrap();
    assert_eq!(mode(&old), 0o600);
}

#[test]
fn rich_content_embeds_callouts_and_bare_links() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic", "viewer");
    let target = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Target", "content": "Hi", "status": "published" })), &admin);
    let tid = target["id"].as_str().unwrap();
    let content = format!(
        "> [!WARNING]\n> Turn the water off first.\n\n\
         [How to unlock the thermostat](https://www.youtube.com/watch?v=9pasx0ghADM)\n\n\
         https://docs.google.com/spreadsheets/d/1Sescq7Qe50UoB9UNhjthBSN1YmSV7FkBn3uTv6yd0ak/edit#gid=0\n\n\
         <iframe src=\"https://evil.example/\"></iframe>\n\n\
         Related: https://kb.acme.test/p/{tid}/target"
    );
    let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Thermostat", "content": content, "status": "published" })), &admin);
    let pid = post["id"].as_str().unwrap();

    let got = h.ok("GET", &format!("/api/v1/posts/{pid}?format=html"), None, &viewer);
    let html = got["html"].as_str().unwrap();
    assert!(html.contains("<blockquote class=\"md-callout md-callout-warning\">"), "{html}");
    assert!(html.contains("<iframe src=\"https://www.youtube-nocookie.com/embed/9pasx0ghADM\""), "{html}");
    assert!(
        html.contains("<iframe src=\"https://docs.google.com/spreadsheets/d/1Sescq7Qe50UoB9UNhjthBSN1YmSV7FkBn3uTv6yd0ak/preview#gid=0\""),
        "{html}"
    );
    assert!(!html.contains("evil.example"), "{html}");
    assert_eq!(html.matches("<iframe ").count(), 2, "{html}");

    // A bare /p/ URL counts as a backlink, like a Markdown link.
    let t = h.ok("GET", &format!("/api/v1/posts/{tid}"), None, &viewer);
    assert_eq!(t["backlinks"][0]["id"], post["id"]);

    // The preview operation renders the same way.
    let preview = h.ok("POST", "/api/v1/render", Some(json!({ "markdown": "https://vimeo.com/925549059/56f7392e1c" })), &viewer);
    assert!(preview["html"].as_str().unwrap().contains("https://player.vimeo.com/video/925549059?h=56f7392e1c"));
}

#[test]
fn embeds_code_office_forms_files_and_posts() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic", "viewer");
    let share = "https://1drv.ms/w/c/501d3fb1eb052268/EXyzEXyzEXyzEXyzEXyzEXyzEXyzEXyz?e=AbC123";
    let content = format!(
        "https://codepen.io/chriscoyier/pen/gfdDu\n\n\
         https://1drv.ms/x/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2\n\n\
         https://acme.typeform.com/to/u6nXL7\n\n\
         https://www.dropbox.com/s/abc123def456ghi/floor-plan.png?dl=0\n\n\
         https://www.dropbox.com/s/abc123def456ghi/walkthrough.mp4?dl=0\n\n\
         https://x.com/jack/status/20\n\n\
         {share}"
    );
    let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Embeds", "content": content, "status": "published" })), &admin);
    let got = h.ok("GET", &format!("/api/v1/posts/{}?format=html", post["id"].as_str().unwrap()), None, &viewer);
    let html = got["html"].as_str().unwrap();

    // Each frame's whole opening tag, found by its src.
    let frame = |src: &str| -> String {
        let start = html.find(&format!("<iframe src=\"{src}\"")).unwrap_or_else(|| panic!("no frame for {src}: {html}"));
        html[start..start + html[start..].find('>').unwrap() + 1].to_string()
    };
    let code = frame("https://codepen.io/chriscoyier/embed/gfdDu?default-tab=result");
    assert!(code.ends_with(" sandbox=\"allow-scripts allow-same-origin\">"), "{code}");
    assert!(!code.contains("allow=") && !code.contains("allowfullscreen"), "{code}");
    let excel = frame("https://1drv.ms/x/c/501d3fb1eb052268/IQTl3fqe7dWBR4yXmtb3biJLAcQq4RHDzlDdwrPC2xXOtUw?em=2");
    assert!(excel.contains("title=\"Excel: ") && excel.contains("allow-forms allow-presentation\">"), "{excel}");
    let form = frame("https://form.typeform.com/to/u6nXL7");
    assert!(form.ends_with(" sandbox=\"allow-scripts allow-same-origin allow-popups allow-forms\">"), "{form}");
    assert_eq!(html.matches("<iframe ").count(), 3, "{html}");

    // Files show from Dropbox's content host; the X post is a card with no frame.
    assert!(html.contains("<img src=\"https://dl.dropboxusercontent.com/s/abc123def456ghi/floor-plan.png\""), "{html}");
    assert!(html.contains("<video src=\"https://dl.dropboxusercontent.com/s/abc123def456ghi/walkthrough.mp4\" controls"), "{html}");
    assert!(
        html.contains(
            "<figure class=\"embed embed-card\"><a href=\"https://x.com/jack/status/20\" target=\"_blank\" rel=\"noopener noreferrer\">\
             <span class=\"embed-card-title\">@jack</span><span class=\"embed-card-meta\">Post on X</span></a></figure>"
        ),
        "{html}"
    );
    // A OneDrive share link can't be framed, so it stays a plain link.
    assert!(html.contains(&format!("<a href=\"{share}\"")), "{html}");
    assert!(!html.contains("<iframe src=\"https://1drv.ms/w/"), "{html}");
}

// Uploaded images and files.

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR not really an image";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn upload(h: &H, auth: &Auth, name: &str, content_type: Option<&str>, bytes: &[u8], post_id: Option<&str>) -> Res {
    let mut body = json!({ "name": name, "data_base64": b64(bytes) });
    if let Some(t) = content_type {
        body["content_type"] = json!(t);
    }
    if let Some(p) = post_id {
        body["post_id"] = json!(p);
    }
    h.call("POST", "/api/v1/files", Some(body), auth)
}

/// Fetches a file's bytes the way a browser (cookie) or an agent (token) does.
fn fetch(h: &H, path: &str, auth: &Auth) -> Res {
    h.call("GET", path, None, auth)
}

#[test]
fn files_upload_serve_and_stay_safe() {
    let h = H::new();
    let (cookie, admin) = h.setup();
    let (_, member) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");

    // An image is detected from its bytes and gets Markdown that shows it.
    let shot = upload(&h, &member, "Screenshot 2026-10-30 at 9.41.12 AM.png", Some("image/png"), PNG, None);
    assert_eq!(shot.status, 200, "{}", shot.body);
    let f = &shot.body;
    let id = f["id"].as_str().unwrap();
    let path = f["path"].as_str().unwrap().to_string();
    let sha: String = Sha256::digest(PNG).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(f["content_type"], "image/png");
    assert_eq!(f["is_image"], true);
    assert_eq!(f["size"], PNG.len());
    assert_eq!(f["sha256"], sha);
    assert_eq!(path, format!("/files/{id}/Screenshot%202026-10-30%20at%209.41.12%20AM.png"));
    assert_eq!(f["url"], format!("https://kb.test{path}"));
    assert_eq!(f["markdown"], format!("![Screenshot 2026-10-30 at 9.41.12 AM.png]({path})"));
    let rendered = h.ok("POST", "/api/v1/render", Some(json!({ "markdown": f["markdown"] })), &member);
    assert!(rendered["html"].as_str().unwrap().contains(&format!("<img src=\"{path}\"")), "{rendered}");

    // It's private to its uploader until a post uses it; then everyone who can see the post can.
    assert_eq!(fetch(&h, &path, &viewer).status, 404);
    h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Screenshot", "content": f["markdown"], "status": "published" })), &member);

    // Agents without a way to fetch the URL get the bytes through the API.
    let dl = h.ok("GET", &format!("/api/v1/files/{id}/content"), None, &viewer);
    assert_eq!(dl["data_base64"], b64(PNG));
    assert_eq!(dl["file"]["id"], id);

    // Members, viewers and browser sessions can open it, inline, with protective headers.
    assert!(dumbslab_core::http::is_core_path(&path));
    for who in [&member, &viewer, &cookie] {
        let got = fetch(&h, &path, who);
        assert_eq!(got.status, 200);
        assert_eq!(got.bytes, PNG);
    }
    let got = fetch(&h, &path, &viewer);
    assert_eq!(got.header("content-type"), Some("image/png"));
    assert_eq!(got.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(got.header("content-security-policy"), Some("default-src 'none'; sandbox"));
    assert!(got.header("content-disposition").unwrap().starts_with("inline; filename=\"Screenshot"), "{:?}", got.headers);
    assert_eq!(got.header("cache-control"), Some("private, max-age=31536000, immutable"));
    // The name in the URL is only for people; a known version revalidates with 304.
    assert_eq!(fetch(&h, &format!("/files/{id}/renamed.png"), &viewer).bytes, PNG);
    let Auth::Bearer(token) = &viewer else { unreachable!() };
    let revalidate = Request {
        method: "GET".into(),
        path: path.clone(),
        headers: vec![
            ("authorization".into(), format!("Bearer {token}")),
            ("if-none-match".into(), got.header("etag").unwrap().to_string()),
        ],
        origin: "https://kb.test".into(),
        ..Default::default()
    };
    let r = h.send(&revalidate);
    assert_eq!(r.status, 304);
    assert!(r.bytes.is_empty());

    // Signed-out people get nothing, unknown files are 404, and files can't be written here.
    let anon = fetch(&h, &path, &Auth::None);
    assert_eq!(anon.status, 401);
    assert_eq!(anon.header("cache-control"), Some("no-store"));
    assert_eq!(fetch(&h, "/files/nope000000/x.png", &member).status, 404);
    assert_eq!(h.call("POST", &path, Some(json!({})), &member).status, 405);

    // A claim never makes a file render: spoofed images, SVG and HTML download as plain bytes.
    for (name, claim, bytes) in [
        ("fake.png", "image/png", &b"MZ\x90\0 not a png"[..]),
        ("logo.svg", "image/svg+xml", &b"<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>"[..]),
        ("page.html", "text/html", &b"<script>alert(1)</script>"[..]),
    ] {
        let r = upload(&h, &member, name, Some(claim), bytes, None);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.body["content_type"], "application/octet-stream", "{name}");
        assert_eq!(r.body["is_image"], false);
        assert!(r.body["markdown"].as_str().unwrap().starts_with(&format!("[{name}](/files/")), "{}", r.body["markdown"]);
        let got = fetch(&h, r.body["path"].as_str().unwrap(), &member);
        assert_eq!(got.header("content-type"), Some("application/octet-stream"));
        assert!(got.header("content-disposition").unwrap().starts_with("attachment;"));
    }
    // A PDF is detected but downloads; a CSV keeps the type it claims.
    let pdf = upload(&h, &member, "plan.pdf", None, b"%PDF-1.7\n%stuff", None);
    assert_eq!(pdf.body["content_type"], "application/pdf");
    let got = fetch(&h, pdf.body["path"].as_str().unwrap(), &member);
    assert!(got.header("content-disposition").unwrap().starts_with("attachment;"));
    assert_eq!(upload(&h, &member, "data.csv", Some("text/csv"), b"a,b\n1,2\n", None).body["content_type"], "text/csv");

    // Big files are stored in chunks of at most 1 MB and come back intact.
    let mut big = PNG.to_vec();
    big.extend((0..2_500_000u32).map(|i| (i % 251) as u8));
    let r = upload(&h, &member, "big.png", None, &big, None);
    assert_eq!(r.status, 200, "{}", r.body);
    let big_id = r.body["id"].as_str().unwrap();
    assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM file_chunks WHERE file_id = '{big_id}'")), 3);
    assert!(count(&h, "SELECT MAX(length(data)) FROM file_chunks") <= 1024 * 1024);
    assert_eq!(fetch(&h, r.body["path"].as_str().unwrap(), &member).bytes, big);

    // Too large, empty or not base64: refused before anything is stored.
    let stored = count(&h, "SELECT COUNT(*) FROM files");
    let r = upload(&h, &member, "huge.bin", None, &vec![0u8; 10 * 1024 * 1024 + 1], None);
    assert_eq!(r.status, 413);
    assert_eq!(r.body["error"]["code"], "too_large");
    assert_eq!(upload(&h, &member, "empty.txt", None, b"", None).status, 400);
    assert_eq!(h.call("POST", "/api/v1/files", Some(json!({ "name": "x", "data_base64": "%%%" })), &member).status, 400);
    assert_eq!(count(&h, "SELECT COUNT(*) FROM files"), stored);

    // The operations endpoint and MCP run the same operation.
    let gif = json!({ "name": "a.gif", "data_base64": b64(b"GIF89a\x01\0\x01\0") });
    assert_eq!(h.ok("POST", "/api/v1/operations/upload_file", Some(gif), &member)["content_type"], "image/gif");
    let args = json!({ "name": "b.txt", "content_type": "text/plain", "data_base64": b64(b"hello") });
    let r = h.mcp(
        &member,
        "",
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "upload_file", "arguments": args } }),
    );
    assert_eq!(r.body["result"]["structuredContent"]["content_type"], "text/plain", "{}", r.body);
}

#[test]
fn file_access_follows_posts() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (mia_id, mia) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, otto) = h.user(&admin, "otto@acme.test", "Otto Outsider", "member");
    let (_, vic) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");

    // Viewers and read-only tokens can't upload, just as they can't write posts.
    assert_eq!(upload(&h, &vic, "x.png", None, PNG, None).status, 403);
    let ro = h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "ro", "scopes": ["read"] })), &mia)["token"].as_str().unwrap().to_string();
    assert_eq!(upload(&h, &Auth::Bearer(ro), "x.png", None, PNG, None).status, 403);

    // A file for a private post opens only for people who can see the post.
    let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Leadership", "visibility": "private" })), &admin)["id"]
        .as_str()
        .unwrap()
        .to_string();
    h.ok("POST", &format!("/api/v1/topics/{topic}/members"), Some(json!({ "user": "mia@acme.test" })), &admin);
    let post =
        h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Org chart", "topic_ids": [topic], "status": "published" })), &mia)["id"]
            .as_str()
            .unwrap()
            .to_string();
    let chart = upload(&h, &mia, "secret-org-chart.png", None, PNG, Some(&post));
    assert_eq!(chart.status, 200, "{}", chart.body);
    assert_eq!(chart.body["post_id"], post.as_str());
    let chart_id = chart.body["id"].as_str().unwrap().to_string();
    let chart_path = chart.body["path"].as_str().unwrap().to_string();
    assert_eq!(fetch(&h, &chart_path, &mia).status, 200);
    assert_eq!(fetch(&h, &chart_path, &admin).status, 200);
    assert_eq!(fetch(&h, &chart_path, &otto).status, 404);
    assert_eq!(fetch(&h, &chart_path, &vic).status, 404);
    assert_eq!(h.call("GET", &format!("/api/v1/files/{chart_id}"), None, &otto).status, 404);
    assert_eq!(h.call("GET", &format!("/api/v1/files?post_id={post}"), None, &otto).status, 404);
    assert!(!ids(&h.ok("GET", "/api/v1/files", None, &otto)).contains(&chart_id));
    assert_eq!(ids(&h.ok("GET", &format!("/api/v1/files?post_id={post}"), None, &mia)), vec![chart_id.clone()]);
    // Nobody can add a file to a post they can't see.
    assert_eq!(upload(&h, &otto, "x.png", None, PNG, Some(&post)).status, 404);

    // A file uploaded before its post exists is private to its uploader, even to someone who has
    // its id, until the uploader saves a post that uses it. Then it follows that post.
    let early = upload(&h, &mia, "salary-bands.png", None, PNG, None);
    let early_id = early.body["id"].as_str().unwrap().to_string();
    let early_path = early.body["path"].as_str().unwrap().to_string();
    assert_eq!(fetch(&h, &early_path, &otto).status, 404);
    assert_eq!(h.call("GET", &format!("/api/v1/files/{early_id}"), None, &otto).status, 404);
    assert_eq!(h.call("GET", &format!("/api/v1/files/{early_id}/content"), None, &otto).status, 404);
    assert_eq!(fetch(&h, &early_path, &mia).status, 200);
    assert!(!ids(&h.ok("GET", "/api/v1/files", None, &otto)).contains(&early_id));
    let feed = h.ok("GET", "/api/v1/activity?event=file.&limit=200", None, &otto);
    let summaries: Vec<&str> = feed["items"].as_array().unwrap().iter().map(|a| a["summary"].as_str().unwrap()).collect();
    assert!(summaries.iter().all(|s| !s.contains("salary") && !s.contains("org-chart")), "{summaries:?}");
    assert!(feed["items"].as_array().unwrap().iter().all(|a| a["target_id"] != early_id.as_str()), "an unattached file's id stays private");
    let content = format!("See {}", early.body["markdown"].as_str().unwrap());
    let bands = h.ok(
        "POST",
        "/api/v1/posts",
        Some(json!({ "title": "Bands", "content": content, "topic_ids": [topic], "status": "published" })),
        &mia,
    );
    assert_eq!(h.ok("GET", &format!("/api/v1/files/{early_id}"), None, &mia)["post_id"], bands["id"]);
    assert_eq!(fetch(&h, &early_path, &otto).status, 404);
    // Someone else's upload doesn't move into your post.
    let otto_file = upload(&h, &otto, "otto.png", None, PNG, None);
    let otto_id = otto_file.body["id"].as_str().unwrap().to_string();
    let edit = json!({ "edits": [{ "type": "append", "content": otto_file.body["markdown"] }] });
    h.ok("POST", &format!("/api/v1/posts/{post}/edit"), Some(edit), &mia);
    assert!(h.ok("GET", &format!("/api/v1/files/{otto_id}"), None, &otto)["post_id"].is_null());

    // Listing by uploader, with paging.
    let page = h.ok("GET", "/api/v1/files?uploaded_by=me&limit=1", None, &mia);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert!(page["next_cursor"].is_string());
    assert_eq!(h.ok("GET", &format!("/api/v1/files?uploaded_by={mia_id}"), None, &admin)["items"].as_array().unwrap().len(), 2);

    // Only the uploader or an admin deletes a file, and deleting frees its storage.
    assert_eq!(h.call("DELETE", &format!("/api/v1/files/{otto_id}"), None, &mia).status, 404);
    h.ok("DELETE", &format!("/api/v1/files/{otto_id}"), None, &otto);
    assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM file_chunks WHERE file_id = '{otto_id}'")), 0);
    assert_eq!(fetch(&h, otto_file.body["path"].as_str().unwrap(), &otto).status, 404);
    h.ok("DELETE", &format!("/api/v1/files/{chart_id}"), None, &admin);

    // Erasing a post erases its files.
    h.ok("DELETE", &format!("/api/v1/posts/{}?permanent=true", bands["id"].as_str().unwrap()), None, &admin);
    assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM files WHERE id = '{early_id}'")), 0);
    assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM file_chunks WHERE file_id = '{early_id}'")), 0);
}

// ---------------------------------------------------------------------------
// Plans for hosted workspaces.

fn plans(price: Option<&str>) -> dumbslab_core::plan::Plans {
    use dumbslab_core::plan::{Allowance, Plans};
    Plans {
        free: Allowance { storage_bytes: 50 << 20, writes_per_day: 1_000 },
        pro: Allowance { storage_bytes: 5 << 30, writes_per_day: 100_000 },
        stripe_price: price.map(str::to_string),
        price_label: "$8 a month".into(),
        portal_configuration: None,
    }
}

/// A hosted workspace at acme.kb.test (first address `acme`), and its admin.
fn hosted(price: Option<&str>) -> (H, Auth) {
    use dumbslab_core::tenancy::signup_token;
    let mut h = H::new();
    h.cfg = HostConfig {
        base_url: Some("https://acme.kb.test".into()),
        signup_secret: Some("sekret".into()),
        workspace: Some("acme".into()),
        hosting: Some(dumbslab_core::Hosting {
            plans: plans(price),
            home: "acme".into(),
            storage_bytes: 300_000,
            capacity: Default::default(),
        }),
        ..Default::default()
    };
    let token = signup_token("sekret", "acme", chrono::Utc::now().timestamp() + 3600);
    let r = h.call(
        "POST",
        "/api/v1/auth/setup",
        Some(json!({ "setup_token": token, "workspace_name": "Acme", "name": "Ada", "email": "ada@acme.test", "password": "password123" })),
        &Auth::None,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let admin = session_from(&r);
    (h, admin)
}

fn db_run<T>(h: &H, f: impl FnOnce(&dyn dumbslab_core::Db) -> dumbslab_core::ApiResult<T>) -> T {
    h.store
        .with_tx(|db| {
            let r = f(db);
            let ok = r.is_ok();
            (r, ok)
        })
        .unwrap()
        .unwrap()
}

fn stripe_call(r: &Res) -> dumbslab_core::plan::StripeCall {
    r.effects
        .iter()
        .find_map(|e| match e {
            Effect::Stripe(c) => Some(c.clone()),
            _ => None,
        })
        .expect("a Stripe call")
}

/// A subscription bought through this workspace's Checkout (it carries the workspace's billing id).
fn sub(h: &H, id: &str, status: &str) -> dumbslab_core::plan::Subscription {
    dumbslab_core::plan::Subscription {
        id: id.into(),
        customer: "cus_1".into(),
        status: status.into(),
        period_end: Some(1_800_000_000),
        cancel_at_period_end: false,
        billing_id: Some(db_run(h, dumbslab_core::plan::billing_id)),
    }
}

#[test]
fn self_hosted_servers_have_no_plan() {
    let h = H::new();
    let (_, admin) = h.setup();
    let p = h.ok("GET", "/api/v1/plan", None, &admin);
    assert_eq!(p["hosted"], false);
    assert!(p["plan"].is_null() && p["usage"].is_null());
    assert_eq!(h.call("POST", "/api/v1/plan/upgrade", None, &admin).status, 400);
    assert_eq!(h.call("POST", "/api/v1/plan/billing", None, &admin).status, 400);
    // Nothing is metered: writes keep working however many rows were written.
    db_run(&h, |db| dumbslab_core::plan::record_writes(db, chrono::Utc::now(), 1_000_000_000));
    h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Unmetered" })), &admin);
}

#[test]
fn hosted_workspaces_meter_writes() {
    use chrono::{Duration, Utc};
    use dumbslab_core::plan;
    let (mut h, admin) = hosted(Some("price_pro"));
    let (_, member) = h.user(&admin, "mo@acme.test", "Mo", "member");
    let admin_token = Auth::Bearer(
        h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "agent", "scopes": ["read", "write", "admin"] })), &admin)["token"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Runbook", "status": "published" })), &member);
    let post_id = post["id"].as_str().unwrap().to_string();

    let views = || count(&h, &format!("SELECT view_count FROM posts WHERE id = '{post_id}'"));
    let read_page = |h: &H| h.ok("GET", &format!("/api/v1/posts/{post_id}?format=html"), None, &admin);
    read_page(&h);
    assert_eq!(views(), 1, "a person reading the page counts as a view");

    let p = h.ok("GET", "/api/v1/plan", None, &member);
    assert_eq!((p["hosted"].as_bool(), p["plan"].as_str()), (Some(true), Some("free")));
    assert_eq!(p["allowance"]["writes_per_day"], 1_000);
    assert_eq!(p["usage"]["storage_bytes"], 300_000);
    assert_eq!(p["pro"]["available"], true);
    assert_eq!(p["pro"]["price"], "$8 a month");

    // Rows written in the last 24 hours count; older ones don't.
    let now = Utc::now();
    db_run(&h, |db| plan::record_writes(db, now - Duration::hours(25), 5_000));
    db_run(&h, |db| plan::record_writes(db, now, 600));
    assert_eq!(h.ok("GET", "/api/v1/plan", None, &member)["usage"]["writes_24h"], 600);
    h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Still room" })), &member);

    // At the allowance, every way of changing things is refused; reading keeps working.
    db_run(&h, |db| plan::record_writes(db, now, 400));
    let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "Too many" })), &member);
    assert_eq!((r.status, r.body["error"]["code"].as_str()), (429, Some("write_limit")), "{}", r.body);
    assert!(r.body["error"]["message"].as_str().unwrap().contains("Upgrade to Pro"));
    let r = h.call("POST", "/api/v1/operations/create_post", Some(json!({ "title": "Too many" })), &member);
    assert_eq!(r.status, 429);
    let r = h.mcp(&member, "", json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "create_post", "arguments": { "title": "Too many" } } }));
    assert_eq!(r.body["result"]["isError"], true, "{}", r.body);
    // A day later the same reader would count again, but not while writes are paused.
    db_run(&h, |db| db.execute("DELETE FROM post_views", &[]).map(|_| ()));
    read_page(&h);
    assert_eq!(views(), 1, "reads stop counting views once writes are paused");
    h.ok("GET", "/api/v1/search?q=runbook", None, &member);
    h.ok("GET", "/api/v1/export", None, &admin);
    let reg = h.call(
        "POST",
        "/oauth/register",
        Some(json!({ "client_name": "App", "redirect_uris": ["http://localhost:9999/cb"] })),
        &Auth::None,
    );
    assert_eq!(reg.status, 429, "anonymous app registration is a change too: {}", reg.body);

    // Upgrading still works, for admins only, and hands the host a Checkout session for this workspace.
    assert_eq!(h.call("POST", "/api/v1/plan/upgrade", None, &member).status, 403);
    let r = h.call("POST", "/api/v1/plan/upgrade", None, &admin);
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["url"], plan::STRIPE_URL_PENDING, "the host puts Stripe's URL here");
    let via_mcp = h.mcp(
        &admin_token,
        "",
        json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": "upgrade_plan", "arguments": {} } }),
    );
    assert_eq!(via_mcp.body["result"]["structuredContent"]["url"], plan::STRIPE_URL_PENDING, "{}", via_mcp.body);
    assert!(stripe_call(&via_mcp).path == "checkout/sessions");
    let call = stripe_call(&r);
    assert_eq!(call.path, "checkout/sessions");
    let form = |k: &str| call.form.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
    assert_eq!(form("client_reference_id").as_deref(), Some("acme"));
    assert_eq!(form("line_items[0][price]").as_deref(), Some("price_pro"));
    assert_eq!(form("customer_email").as_deref(), Some("ada@acme.test"));
    assert_eq!(h.call("POST", "/api/v1/plan/billing", None, &admin).status, 409, "nothing bought yet");

    // A subscription some other workspace bought (or one made by hand in Stripe) doesn't apply.
    let foreign = plan::Subscription { billing_id: Some("someone-else".into()), ..sub(&h, "sub_x", "active") };
    assert!(!db_run(&h, |db| plan::apply_subscription(db, &foreign)));
    assert!(!db_run(&h, |db| plan::apply_subscription(db, &plan::Subscription { billing_id: None, ..foreign.clone() })));
    assert_eq!(h.ok("GET", "/api/v1/plan", None, &member)["plan"], "free");
    assert_eq!(form("subscription_data[metadata][billing_id]"), sub(&h, "s", "active").billing_id);

    // Stripe reports the subscription: Pro, with its larger allowance.
    assert!({
        let s = sub(&h, "sub_1", "active");
        db_run(&h, |db| plan::apply_subscription(db, &s))
    });
    let p = h.ok("GET", "/api/v1/plan", None, &member);
    assert_eq!(p["plan"], "pro");
    assert_eq!(p["subscription"]["status"], "active");
    assert!(p["subscription"].get("customer").is_none(), "billing ids stay with the host");
    h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Room again" })), &member);
    assert_eq!(h.call("POST", "/api/v1/plan/upgrade", None, &admin).status, 409, "already Pro");
    let r = h.call("POST", "/api/v1/plan/billing", None, &admin);
    assert_eq!(r.status, 200, "{}", r.body);
    let portal = stripe_call(&r);
    assert_eq!(portal.path, "billing_portal/sessions");
    assert!(portal.form.contains(&("customer".into(), "cus_1".into())));
    assert!(portal.form.contains(&("return_url".into(), "https://acme.kb.test/settings/plan".into())));

    // A failed renewal keeps Pro while Stripe retries; news about an older subscription is ignored.
    {
        let s = sub(&h, "sub_1", "past_due");
        db_run(&h, |db| plan::apply_subscription(db, &s))
    };
    assert_eq!(h.ok("GET", "/api/v1/plan", None, &member)["plan"], "pro");
    {
        let s = sub(&h, "sub_1", "active");
        db_run(&h, |db| plan::apply_subscription(db, &s))
    };
    assert!(!{
        let s = sub(&h, "sub_0", "canceled");
        db_run(&h, |db| plan::apply_subscription(db, &s))
    });
    assert_eq!(h.ok("GET", "/api/v1/plan", None, &member)["plan"], "pro");

    // Changes to the subscription the workspace holds apply even if its billing id went missing
    // (say, metadata edited in the Stripe Dashboard), so a cancellation is never ignored.
    let edited = plan::Subscription { billing_id: None, cancel_at_period_end: true, ..sub(&h, "sub_1", "active") };
    assert!(db_run(&h, |db| plan::apply_subscription(db, &edited)));
    assert_eq!(h.ok("GET", "/api/v1/plan", None, &member)["subscription"]["cancel_at_period_end"], true);

    // Cancelled: back to free. Upgrading again reuses the Stripe customer.
    {
        let s = sub(&h, "sub_1", "canceled");
        db_run(&h, |db| plan::apply_subscription(db, &s))
    };
    assert_eq!(h.ok("GET", "/api/v1/plan", None, &member)["plan"], "free");
    assert_eq!(h.call("POST", "/api/v1/posts", Some(json!({ "title": "Over" })), &member).status, 429);
    let call = stripe_call(&h.call("POST", "/api/v1/plan/upgrade", None, &admin));
    assert!(call.form.contains(&("customer".into(), "cus_1".into())));
    assert_eq!(h.call("POST", "/api/v1/plan/billing", None, &admin).status, 200, "invoices stay reachable");

    // When the free plan is at capacity, free workspaces pause; Pro ones (here, granted) don't.
    db_run(&h, |db| db.execute("DELETE FROM usage_hours", &[]).map(|_| ()));
    h.cfg.hosting.as_mut().unwrap().capacity.writes_paused = true;
    let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "Busy" })), &member);
    assert_eq!((r.status, r.body["error"]["code"].as_str()), (503, Some("free_capacity")), "{}", r.body);
    db_run(&h, |db| plan::set_grant(db, true));
    let p = h.ok("GET", "/api/v1/plan", None, &member);
    assert_eq!((p["plan"].as_str(), p["granted"].as_bool()), (Some("pro"), Some(true)));
    h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Granted" })), &member);
    db_run(&h, |db| plan::set_grant(db, false));
    assert_eq!(h.call("POST", "/api/v1/posts", Some(json!({ "title": "Busy" })), &member).status, 503);
}

#[test]
fn hosted_bookkeeping_stays_within_limits() {
    let (mut h, admin) = hosted(Some("price_pro"));
    let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Page", "status": "published" })), &admin);
    let id = post["id"].as_str().unwrap().to_string();
    let views = |h: &H| count(h, &format!("SELECT COUNT(*) FROM post_views WHERE post_id = '{id}'"));
    // A full workspace stops recording views, which would grow it.
    h.cfg.hosting.as_mut().unwrap().storage_bytes = 50 << 20;
    h.ok("GET", &format!("/api/v1/posts/{id}?format=html"), None, &admin);
    assert_eq!(views(&h), 0);
    h.cfg.hosting.as_mut().unwrap().storage_bytes = 300_000;
    h.ok("GET", &format!("/api/v1/posts/{id}?format=html"), None, &admin);
    assert_eq!(views(&h), 1);

    // Anonymous app registration is capped per hour.
    for _ in 0..dumbslab_core::oauth::HOSTED_REGISTRATIONS_PER_HOUR {
        register_app(&h);
    }
    let r = h.call(
        "POST",
        "/oauth/register",
        Some(json!({ "client_name": "One more", "redirect_uris": ["http://localhost:9999/cb"] })),
        &Auth::None,
    );
    assert_eq!(r.status, 429, "{}", r.body);
}

#[test]
fn pro_is_not_for_sale_without_stripe() {
    let (h, admin) = hosted(None);
    let p = h.ok("GET", "/api/v1/plan", None, &admin);
    assert_eq!(p["pro"]["available"], false);
    let r = h.call("POST", "/api/v1/plan/upgrade", None, &admin);
    assert_eq!((r.status, r.body["error"]["code"].as_str()), (503, Some("unavailable")));
    assert!(r.effects.is_empty());
    // Limit messages don't offer what can't be bought.
    db_run(&h, |db| dumbslab_core::plan::record_writes(db, chrono::Utc::now(), 1_000));
    let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "x" })), &admin);
    assert!(r.body["error"]["message"].as_str().unwrap().contains("self-host"), "{}", r.body);
}

#[test]
fn directory_budgets_the_free_plan() {
    use chrono::{Duration, Utc};
    use dumbslab_core::tenancy::{self, FreeBudget, Limits};
    let h = H::new();
    let budget = FreeBudget { writes_per_day: 1_000, storage_bytes: 10_000 };
    let limits = Limits { per_ip_per_day: 50, per_day: 50, max_workspaces: 50, free: budget };
    let t0 = Utc::now();
    db_run(&h, tenancy::directory_migrate);
    let cap = |at| db_run(&h, |db| tenancy::free_capacity(db, at, budget));
    let report = |home: &'static str, plan: &'static str, writes, storage, at| {
        db_run(&h, move |db| tenancy::report_usage(db, home, plan, writes, storage, at))
    };
    for slug in ["acme", "beta", "gamma"] {
        db_run(&h, |db| tenancy::reserve(db, slug, "Name", slug, t0, limits).map(|_| ()));
        db_run(&h, |db| tenancy::activate(db, slug, t0));
    }
    assert_eq!(cap(t0), Default::default());

    // Free workspaces' latest reports add up; Pro ones don't count.
    report("acme", "free", 600, 4_000, t0);
    report("beta", "pro", 50_000, 900_000, t0);
    assert_eq!(cap(t0), Default::default());
    report("gamma", "free", 400, 6_000, t0);
    let full = cap(t0);
    assert!(full.writes_paused && full.growth_paused);
    let r = h.store.with_tx(|db| (tenancy::reserve(db, "delta", "Name", "ip", t0, limits), false)).unwrap();
    assert_eq!(r.map_err(|e| e.status).err(), Some(503), "sign-ups pause at capacity");
    // A newer report replaces the old one, and day-old reports stop counting toward writes.
    report("gamma", "free", 100, 1_000, t0);
    assert_eq!(cap(t0), Default::default());
    report("acme", "free", 990, 4_000, t0 - Duration::hours(30));
    assert!(!cap(t0).writes_paused);
    assert!(db_run(&h, |db| tenancy::free_usage(db, t0)).storage_bytes == 5_000);
    // A plan name the directory doesn't know is refused.
    assert!(h.store.with_tx(|db| (tenancy::report_usage(db, "acme", "gold", 1, 1, t0), false)).unwrap().is_err());

    // Stripe customers map to their workspace; a paying workspace says so.
    assert!(!db_run(&h, |db| tenancy::paying(db, "beta")));
    db_run(&h, |db| tenancy::link_customer(db, "cus_9", "beta", t0));
    assert_eq!(db_run(&h, |db| tenancy::customer_home(db, "cus_9")), tenancy::Payer::Workspace("beta".into()));
    assert_eq!(db_run(&h, |db| tenancy::customer_home(db, "cus_x")), tenancy::Payer::Unknown);
    db_run(&h, |db| tenancy::record_subscription(db, "cus_9", "sub_9", "active", t0));
    assert!(db_run(&h, |db| tenancy::paying(db, "beta")));
    db_run(&h, |db| tenancy::record_risk(db, "cus_9", "charge.dispute.created", t0));
    let entries = db_run(&h, tenancy::list);
    let beta = entries.iter().find(|e| e.slug == "beta").unwrap();
    assert_eq!((beta.plan.as_deref(), beta.billing_status.as_deref()), (Some("pro"), Some("active")));
    assert!(beta.billing_risk.as_deref().unwrap().starts_with("charge.dispute.created"));
    let acme = entries.iter().find(|e| e.slug == "acme").unwrap();
    assert_eq!((acme.writes_24h, acme.storage_bytes, acme.billing_status.clone()), (Some(990), Some(4_000), None));
    db_run(&h, |db| tenancy::record_subscription(db, "cus_9", "sub_9", "canceled", t0));
    assert!(!db_run(&h, |db| tenancy::paying(db, "beta")));

    // Removing a workspace drops its usage and detaches who paid for it, for good: someone else
    // may claim the address, and the old customer's late events must not reach them.
    db_run(&h, |db| tenancy::remove(db, "acme"));
    assert_eq!(db_run(&h, |db| tenancy::free_usage(db, t0)).storage_bytes, 1_000);
    db_run(&h, |db| tenancy::record_subscription(db, "cus_9", "sub_9", "active", t0));
    db_run(&h, |db| tenancy::remove(db, "beta"));
    assert_eq!(db_run(&h, |db| tenancy::customer_home(db, "cus_9")), tenancy::Payer::Detached);
    db_run(&h, |db| tenancy::reserve(db, "beta", "Name", "ip-new", t0 + Duration::days(2), limits).map(|_| ()));
    db_run(&h, |db| tenancy::activate(db, "beta", t0 + Duration::days(2)));
    assert!(!db_run(&h, |db| tenancy::paying(db, "beta")), "the new owner isn't the old payer");
    db_run(&h, |db| tenancy::link_customer(db, "cus_9", "beta", t0));
    assert_eq!(db_run(&h, |db| tenancy::customer_home(db, "cus_9")), tenancy::Payer::Detached, "stays detached");
    db_run(&h, |db| tenancy::link_customer(db, "cus_new", "beta", t0));
    assert_eq!(db_run(&h, |db| tenancy::customer_home(db, "cus_new")), tenancy::Payer::Workspace("beta".into()));
    let entries = db_run(&h, tenancy::list);
    assert_eq!(entries.iter().find(|e| e.slug == "beta").unwrap().billing_status, None);
}

// ---------------------------------------------------------------------------
// Connected apps. The tests play the host: they run each job's steps with canned answers.

mod connected {
    use super::*;
    use dumbslab_core::connect::{self, Finish, HttpCall, HttpReply, Job, OAuthApp, Step};

    fn with_key(h: &mut H) {
        h.cfg.connectors.key = Some("connector-key".into());
    }

    fn job_of(r: &Res) -> Job {
        r.effects
            .iter()
            .find_map(|e| match e {
                Effect::Connect(j) => Some(j.clone()),
                _ => None,
            })
            .expect("a connected-apps job")
    }

    /// Runs a job, answering each step's requests with `answer`. Returns how it finished and every
    /// request it made.
    fn drive(h: &H, mut job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Finish, Vec<HttpCall>) {
        let mut replies = vec![];
        let mut sent = vec![];
        for _ in 0..connect::MAX_STEPS {
            let (step, next) = h
                .store
                .with_tx(|db| {
                    let step = connect::step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now());
                    let ok = step.is_ok();
                    ((step, job.clone()), ok)
                })
                .unwrap();
            job = next;
            match step.unwrap() {
                Step::Done(f) => return (f, sent),
                Step::Fetch(calls) => {
                    replies = calls.iter().map(answer).collect();
                    sent.extend(calls);
                }
            }
        }
        panic!("job didn't finish");
    }

    fn filled(r: &Res, finish: Finish) -> Value {
        match finish {
            Finish::Fill(v) => connect::fill(r.body.clone(), Ok(v)).expect("a placeholder to fill"),
            other => panic!("expected a result, got {other:?}"),
        }
    }

    /// Runs one step of a job.
    fn step(h: &H, job: &mut Job, replies: Vec<HttpReply>) -> Step {
        h.store
            .with_tx(|db| {
                let step = connect::step(db, &h.cfg, job, replies, chrono::Utc::now());
                let ok = step.is_ok();
                (step, ok)
            })
            .unwrap()
            .unwrap()
    }

    fn fetches(step: Step) -> Vec<HttpCall> {
        match step {
            Step::Fetch(calls) => calls,
            other => panic!("expected requests, got {other:?}"),
        }
    }

    fn result(step: Step) -> Value {
        match step {
            Step::Done(Finish::Fill(v)) => v,
            other => panic!("expected a result, got {other:?}"),
        }
    }

    fn ok(body: Value) -> HttpReply {
        HttpReply { status: 200, body: body.to_string() }
    }

    /// GitHub, answering as the account `ada` in org `acme`.
    fn github(call: &HttpCall) -> HttpReply {
        let url = call.url.as_str();
        if url.ends_with("/user") {
            ok(json!({ "login": "ada" }))
        } else if url.contains("/user/orgs") {
            ok(json!([{ "login": "acme" }]))
        } else if url.contains("/search/issues") {
            ok(
                json!({ "items": [{ "title": "Deploy fails", "html_url": "https://github.com/acme/api/issues/7", "number": 7, "state": "open",
                "repository_url": "https://api.github.com/repos/acme/api", "user": { "login": "bo" } }] }),
            )
        } else if url.contains("/search/repositories") {
            ok(json!({ "items": [] }))
        } else if url.contains("/repos/acme/api/issues/7") {
            ok(
                json!({ "title": "Deploy fails", "html_url": "https://github.com/acme/api/issues/7", "state": "open", "user": { "login": "bo" } }),
            )
        } else if url.contains("login/oauth/access_token") {
            ok(json!({ "access_token": "gho_from_oauth", "token_type": "bearer" }))
        } else {
            HttpReply { status: 404, body: "{}".into() }
        }
    }

    fn connect_github(h: &H, auth: &Auth) {
        let r = h.call("POST", "/api/v1/connections", Some(json!({ "app": "github", "fields": { "token": "ghp_secret_token" } })), auth);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(h, job_of(&r), &github);
        assert!(sent.iter().all(|c| c.headers.contains(&("authorization".into(), "Bearer ghp_secret_token".into()))));
        let v = filled(&r, finish);
        assert_eq!(v["connection"]["account"], "@ada", "{v}");
    }

    #[test]
    fn people_connect_and_search_their_own_apps() {
        let mut h = H::new();
        let (admin, admin_token) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");

        // Without a connector key, nothing can be connected.
        let list = h.ok("GET", "/api/v1/connections", None, &admin);
        assert_eq!(list["enabled"], false);
        assert_eq!(h.call("POST", "/api/v1/connections", Some(json!({ "app": "github", "fields": { "token": "t" } })), &admin).status, 503);

        with_key(&mut h);
        let list = h.ok("GET", "/api/v1/connections", None, &admin);
        let gh = list["apps"].as_array().unwrap().iter().find(|a| a["id"] == "github").unwrap().clone();
        assert_eq!((gh["sign_in"].as_bool(), gh["search"].as_bool(), gh["preview"].as_bool()), (Some(false), Some(true), Some(true)));
        assert!(gh["connected"].is_null());
        let bad = |fields: Value| h.call("POST", "/api/v1/connections", Some(json!({ "app": "github", "fields": fields })), &admin).status;
        assert_eq!(bad(json!({})), 400, "a token is required");
        assert_eq!(bad(json!({ "token": "t", "password": "x" })), 400, "unknown fields are refused");
        assert_eq!(h.call("POST", "/api/v1/connections", Some(json!({ "app": "nope" })), &admin).status, 400);
        assert_eq!(
            h.call("POST", "/api/v1/connections", Some(json!({ "app": "google-drive", "fields": { "token": "t" } })), &admin).status,
            400
        );

        // A bad token is refused and nothing is saved.
        let r = h.call("POST", "/api/v1/connections", Some(json!({ "app": "github", "fields": { "token": "wrong" } })), &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_| HttpReply { status: 401, body: "{}".into() });
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("rejected")), "{finish:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM connections"), 0);

        connect_github(&h, &admin);
        // The token is encrypted at rest and never comes back.
        let secret: String =
            h.store.with_tx(|db| (db.one("SELECT secret FROM connections", &[]).unwrap().unwrap().str("secret"), true)).unwrap();
        assert!(!secret.contains("ghp_secret_token"));
        let list = h.ok("GET", "/api/v1/connections", None, &admin);
        assert!(!list.to_string().contains("ghp_secret_token"));
        let gh = list["apps"].as_array().unwrap().iter().find(|a| a["id"] == "github").unwrap().clone();
        assert_eq!(gh["connected"]["account"], "@ada");

        // Search uses the person's own token and scope; results fill the answer over REST and MCP.
        let r = h.call("GET", "/api/v1/search/connected?q=deploy", None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(&h, job_of(&r), &github);
        assert!(sent[0].url.contains("q=deploy%20user%3Aada%20org%3Aacme"), "{:?}", sent[0].url);
        let v = filled(&r, finish);
        assert_eq!(v["items"][0]["title"], "Deploy fails");
        assert_eq!(v["apps"][0]["ok"], true);
        let via_mcp = h.mcp(&admin_token, "", json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "search_connected", "arguments": { "q": "deploy" } } }));
        let (finish, _) = drive(&h, job_of(&via_mcp), &github);
        let v = filled(&via_mcp, finish);
        assert_eq!(v["result"]["structuredContent"]["items"][0]["kind"], "issue");

        // Someone else has no connections, so nothing is searched for them.
        let r = h.call("GET", "/api/v1/search/connected?q=deploy", None, &mo);
        assert!(r.effects.is_empty());
        assert_eq!(r.body["items"], json!([]));

        // Previews: a connected app's link is read with the viewer's account.
        let r = h.call("GET", "/api/v1/connections/preview?url=https%3A%2F%2Fgithub.com%2Facme%2Fapi%2Fissues%2F7", None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &github);
        let v = filled(&r, finish);
        assert_eq!((v["app"].as_str(), v["preview"]["reference"].as_str()), (Some("github"), Some("acme/api #7")));
        // Not connected: the app is named so the UI can suggest connecting it, and nothing is fetched.
        let r = h.call("GET", "/api/v1/connections/preview?url=https%3A%2F%2Fgithub.com%2Facme%2Fapi%2Fissues%2F7", None, &mo);
        assert!(r.effects.is_empty());
        assert_eq!((r.body["app"].as_str(), r.body["connected"].as_bool()), (Some("github"), Some(false)));
        // Apps on a customer's own address too.
        for (url, app) in [("https://acme.atlassian.net/browse/OPS-12", "jira"), ("https://acme.monday.com/boards/1/pulses/2", "monday")] {
            let r = h.call("GET", &format!("/api/v1/connections/preview?url={}", urlencoding::encode(url)), None, &mo);
            assert_eq!((r.body["app"].as_str(), r.body["connected"].as_bool()), (Some(app), Some(false)), "{url}");
        }
        let r = h.call("GET", "/api/v1/connections/preview?url=https%3A%2F%2Fexample.com%2Fx", None, &admin);
        assert!(r.effects.is_empty() && r.body["app"].is_null());

        // Disconnecting forgets the credentials.
        h.ok("DELETE", "/api/v1/connections/github", None, &admin);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM connections"), 0);
        assert_eq!(h.call("DELETE", "/api/v1/connections/github", None, &admin).status, 404);
    }

    #[test]
    fn signing_in_with_an_app() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        with_key(&mut h);
        assert_eq!(h.call("POST", "/api/v1/connections", Some(json!({ "app": "github" })), &admin).status, 400, "no OAuth app yet");
        h.cfg.connectors.apps.insert("github".into(), OAuthApp { client_id: "cid".into(), client_secret: "csecret".into() });
        assert_eq!(h.ok("GET", "/api/v1/connections", None, &admin)["apps"][0]["sign_in"], true);

        let start = |auth: &Auth| {
            let url =
                h.ok("POST", "/api/v1/connections", Some(json!({ "app": "github" })), auth)["authorize_url"].as_str().unwrap().to_string();
            assert!(url.starts_with("https://github.com/login/oauth/authorize?"), "{url}");
            let q = query_of(&url);
            assert_eq!((q["client_id"].as_str(), q["redirect_uri"].as_str()), ("cid", "https://kb.test/connect/callback"));
            assert_eq!(q["scope"], "repo read:org");
            q["state"].clone()
        };
        let callback = |state: &str, auth: &Auth| {
            h.call("GET", &format!("/connect/callback?code=the-code&state={}", urlencoding::encode(state)), None, auth)
        };
        let location = |r: &Res| r.header("location").unwrap_or_default().to_string();

        // The person who started must be the one coming back.
        let state = start(&admin);
        let r = callback(&state, &mo);
        // Links back to Settings carry only a code (and the app), never text anyone could write.
        assert_eq!(location(&r), "https://kb.test/settings/connections?connect_error=wrong_person&app=github");
        assert!(r.effects.is_empty());
        assert_eq!(
            location(&callback(&state, &admin)),
            "https://kb.test/settings/connections?connect_error=expired_link",
            "a state works once"
        );

        // Success: the code is exchanged with the client secret, the account read, and the person sent to Settings.
        let state = start(&admin);
        let r = callback(&state, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &github);
        let exchange = &sent[0];
        assert_eq!(exchange.url, "https://github.com/login/oauth/access_token");
        let body = exchange.body.clone().unwrap();
        assert!(
            body.contains("code=the-code")
                && body.contains("client_secret=csecret")
                && body.contains("redirect_uri=https%3A%2F%2Fkb.test%2Fconnect%2Fcallback"),
            "{body}"
        );
        assert!(sent[1].headers.contains(&("authorization".into(), "Bearer gho_from_oauth".into())));
        assert!(matches!(&finish, Finish::Redirect(u) if u == "https://kb.test/settings/connections?connected=github"), "{finish:?}");
        assert_eq!(h.ok("GET", "/api/v1/connections", None, &admin)["apps"][0]["connected"]["account"], "@ada");

        // A failed exchange lands back in Settings with a code, not GitHub's answer.
        let state = start(&admin);
        let refused = |_: &HttpCall| HttpReply {
            status: 400,
            body: json!({ "error": "bad_verification_code", "error_description": "Call 555-0100" }).to_string(),
        };
        let (finish, _) = drive(&h, job_of(&callback(&state, &admin)), &refused);
        assert!(
            matches!(&finish, Finish::Redirect(u) if u == "https://kb.test/settings/connections?connect_error=failed&app=github"),
            "{finish:?}"
        );

        // The app saying no lands back in Settings.
        let state = start(&admin);
        let r = h.call(
            "GET",
            &format!("/connect/callback?error=access_denied&error_description=The+user+said+no&state={}", urlencoding::encode(&state)),
            None,
            &admin,
        );
        assert_eq!(location(&r), "https://kb.test/settings/connections?connect_error=declined&app=github", "the app's own words stay out");
        assert!(r.effects.is_empty());

        // Hosted workspaces name themselves in the state, so the root domain can forward the person.
        let mut hosted = h;
        hosted.cfg.workspace = Some("acme".into());
        let url = hosted.ok("POST", "/api/v1/connections", Some(json!({ "app": "github" })), &admin)["authorize_url"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(query_of(&url)["state"].starts_with("acme."));
    }

    #[test]
    fn a_late_refresh_never_lands_on_a_replaced_connection() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.cfg.connectors.apps.insert("gitlab".into(), OAuthApp { client_id: "gl".into(), client_secret: "glsecret".into() });
        let user_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        // A gitlab.com connection whose token has expired.
        let cred = connect::Credential { token: "com-old".into(), refresh_token: Some("com-refresh".into()), ..Default::default() };
        let sealed = connect::seal("connector-key", &user_id, "gitlab", &cred).unwrap();
        let past = dumbslab_core::util::ts(chrono::Utc::now() - chrono::Duration::hours(1));
        h.store
            .with_tx(|db| {
                (db.execute(
                    "INSERT INTO connections (user_id, provider, account, settings, secret, expires_at, created_at, updated_at) VALUES (?, 'gitlab', '@ada', ?, ?, ?, ?, ?)",
                    &dumbslab_core::params![user_id.clone(), json!({ "host": "gitlab.com", "username": "ada" }).to_string(), sealed, past.clone(), past.clone(), past.clone()],
                ), true)
            })
            .unwrap()
            .unwrap();
        let preview =
            |url: &str| job_of(&h.call("GET", &format!("/api/v1/connections/preview?url={}", urlencoding::encode(url)), None, &admin));

        // A preview starts refreshing the gitlab.com token...
        let mut late = preview("https://gitlab.com/acme/api/-/issues/3");
        assert!(fetches(step(&h, &mut late, vec![]))[0].url.starts_with("https://gitlab.com/oauth/token"));
        // ...while the person connects their own GitLab server instead.
        let fields = json!({ "app": "gitlab", "fields": { "token": "self-token", "base_url": "https://gitlab.example.com" } });
        let r = h.call("POST", "/api/v1/connections", Some(fields), &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_: &HttpCall| ok(json!({ "username": "ada" })));
        assert!(filled(&r, finish)["connection"]["account"].as_str().unwrap().contains("gitlab.example.com"));

        // The gitlab.com tokens arrive late: they're dropped, not saved over the new connection.
        let tokens = ok(json!({ "access_token": "com-new", "refresh_token": "com-refresh-2", "expires_in": 7200 }));
        let v = result(step(&h, &mut late, vec![tokens]));
        assert!(v["error"].as_str().unwrap().contains("connected again"), "{v}");
        let secret = h.store.with_tx(|db| (db.one("SELECT secret FROM connections", &[]).unwrap().unwrap().str("secret"), true)).unwrap();
        assert_eq!(connect::open("connector-key", &user_id, "gitlab", &secret).unwrap().token, "self-token");
        // So the new server only ever gets its own token.
        let (_, sent) = drive(&h, preview("https://gitlab.example.com/acme/api/-/issues/3"), &|_: &HttpCall| ok(json!({ "title": "x" })));
        assert!(sent[0].url.starts_with("https://gitlab.example.com/"));
        assert!(sent[0].headers.contains(&("authorization".into(), "Bearer self-token".into())), "{sent:?}");
    }

    #[test]
    fn previews_follow_the_connection_as_it_is_now() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.cfg.connectors.apps.insert("gitlab".into(), OAuthApp { client_id: "gl".into(), client_secret: "glsecret".into() });
        let user_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        let gitlab_com = |expires: chrono::DateTime<chrono::Utc>| {
            let cred = connect::Credential { token: "com-old".into(), refresh_token: Some("com-refresh".into()), ..Default::default() };
            let sealed = connect::seal("connector-key", &user_id, "gitlab", &cred).unwrap();
            let (expires, now) = (dumbslab_core::util::ts(expires), dumbslab_core::util::ts(chrono::Utc::now()));
            let settings = json!({ "host": "gitlab.com", "username": "ada" }).to_string();
            h.store
                .with_tx(|db| {
                    db.execute("DELETE FROM connections", &[]).unwrap();
                    (db.execute(
                        "INSERT INTO connections (user_id, provider, account, settings, secret, expires_at, created_at, updated_at) VALUES (?, 'gitlab', '@ada', ?, ?, ?, ?, ?)",
                        &dumbslab_core::params![user_id.clone(), settings, sealed, expires, now.clone(), now],
                    ), true)
                })
                .unwrap()
                .unwrap();
        };
        let own_server = || {
            let fields = json!({ "app": "gitlab", "fields": { "token": "self-token", "base_url": "https://gitlab.example.com" } });
            drive(&h, job_of(&h.call("POST", "/api/v1/connections", Some(fields), &admin)), &|_: &HttpCall| {
                ok(json!({ "username": "ada" }))
            });
        };
        let link = format!("/api/v1/connections/preview?url={}", urlencoding::encode("https://gitlab.com/acme/api/-/issues/3"));
        let preview = || job_of(&h.call("GET", &link, None, &admin));
        let error = |step: Step| result(step)["error"].as_str().unwrap_or_default().to_string();
        let (past, later) = (chrono::Utc::now() - chrono::Duration::hours(1), chrono::Utc::now() + chrono::Duration::hours(1));

        // The refresh is refused because the person connected their own server meanwhile: the
        // gitlab.com link isn't on that server, so nothing is fetched from it.
        gitlab_com(past);
        let mut job = preview();
        fetches(step(&h, &mut job, vec![]));
        own_server();
        let refused = HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() };
        assert!(error(step(&h, &mut job, vec![refused])).contains("connected again"));
        // The same when the change comes before the preview starts.
        gitlab_com(later);
        let mut job = preview();
        own_server();
        assert!(error(step(&h, &mut job, vec![])).contains("connected again"));
        // A disconnected app's token isn't used at all.
        gitlab_com(later);
        let mut job = preview();
        h.ok("DELETE", "/api/v1/connections/gitlab", None, &admin);
        assert!(error(step(&h, &mut job, vec![])).contains("isn't connected any more"));
    }

    #[test]
    fn expired_tokens_are_refreshed_first() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.cfg.connectors.apps.insert("google-drive".into(), OAuthApp { client_id: "gid".into(), client_secret: "gsecret".into() });
        h.cfg.connectors.apps.insert("linear".into(), OAuthApp { client_id: "lid".into(), client_secret: "lsecret".into() });
        let user_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        // A Drive connection whose access token expired an hour ago.
        let cred = connect::Credential { token: "old".into(), refresh_token: Some("refresh-1".into()), ..Default::default() };
        let sealed = connect::seal("connector-key", &user_id, "google-drive", &cred).unwrap();
        let past = dumbslab_core::util::ts(chrono::Utc::now() - chrono::Duration::hours(1));
        // And an expired Linear one: Linear only previews links, so searching leaves it alone.
        let linear = connect::seal("connector-key", &user_id, "linear", &cred).unwrap();
        h.store
            .with_tx(|db| {
                let insert = "INSERT INTO connections (user_id, provider, account, settings, secret, expires_at, created_at, updated_at) VALUES (?, ?, 'ada@acme.test', '{}', ?, ?, ?, ?)";
                for (app, sealed) in [("google-drive", &sealed), ("linear", &linear)] {
                    db.execute(insert, &dumbslab_core::params![user_id.clone(), app, sealed.clone(), past.clone(), past.clone(), past.clone()]).unwrap();
                }
                ((), true)
            })
            .unwrap();
        let r = h.call("GET", "/api/v1/search/connected?q=budget", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &|c: &HttpCall| {
            if c.url.contains("oauth2.googleapis.com/token") {
                ok(json!({ "access_token": "new", "expires_in": 3600 }))
            } else {
                ok(
                    json!({ "files": [{ "name": "Budget", "mimeType": "application/vnd.google-apps.spreadsheet", "webViewLink": "https://docs.google.com/x" }] }),
                )
            }
        });
        assert!(
            sent[0].body.as_deref().unwrap().contains("grant_type=refresh_token")
                && sent[0].body.as_deref().unwrap().contains("refresh_token=refresh-1")
        );
        assert!(sent[1].headers.contains(&("authorization".into(), "Bearer new".into())), "searches with the new token");
        assert!(!sent.iter().any(|c| c.url.contains("linear")), "{sent:?}");
        let v = filled(&r, finish);
        assert_eq!((v["items"][0]["kind"].as_str(), v["apps"].as_array().unwrap().len()), (Some("spreadsheet"), 1), "{v}");
        // The new token was saved, encrypted.
        let (secret, expires): (String, String) = h
            .store
            .with_tx(|db| {
                let row = db.one("SELECT secret, expires_at FROM connections WHERE provider = 'google-drive'", &[]).unwrap().unwrap();
                ((row.str("secret"), row.str("expires_at")), true)
            })
            .unwrap();
        assert_eq!(connect::open("connector-key", &user_id, "google-drive", &secret).unwrap().token, "new");
        assert!(expires > dumbslab_core::util::ts(chrono::Utc::now()));

        // Two searches at once. Refresh tokens that work only once (Box, Atlassian) mean only the
        // first may refresh; the second keeps using the current token, still good for a while.
        let set = |token: &str, refresh: &str, expires: String| {
            let cred = connect::Credential { token: token.into(), refresh_token: Some(refresh.into()), ..Default::default() };
            let sealed = connect::seal("connector-key", &user_id, "google-drive", &cred).unwrap();
            h.store
                .with_tx(|db| {
                    (
                        db.execute(
                            "UPDATE connections SET secret = ?, expires_at = ? WHERE provider = 'google-drive'",
                            &dumbslab_core::params![sealed, expires],
                        ),
                        true,
                    )
                })
                .unwrap()
                .unwrap();
        };
        let search = || job_of(&h.call("GET", "/api/v1/search/connected?q=budget", None, &admin));
        let bearer = |calls: &[HttpCall]| {
            calls.iter().find_map(|c| c.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone())).unwrap_or_default()
        };
        set("new", "refresh-2", dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::minutes(2)));
        let (mut first, mut second) = (search(), search());
        let refreshing = fetches(step(&h, &mut first, vec![]));
        assert!(refreshing[0].body.as_deref().unwrap().contains("refresh_token=refresh-2"));
        assert_eq!(bearer(&fetches(step(&h, &mut second, vec![]))), "Bearer new", "the second searches with the current token");
        let tokens = ok(json!({ "access_token": "newer", "refresh_token": "refresh-3", "expires_in": 3600 }));
        assert_eq!(bearer(&fetches(step(&h, &mut first, vec![tokens]))), "Bearer newer");

        // Once the token has expired, the second asks to try again, not to reconnect.
        set("newer", "refresh-3", past.clone());
        let (mut first, mut second) = (search(), search());
        fetches(step(&h, &mut first, vec![]));
        let v = result(step(&h, &mut second, vec![]));
        assert!(v["apps"][0]["error"].as_str().unwrap().contains("Try again in a moment"), "{v}");
        // The refresh times out: not a reason to reconnect either, and the next search refreshes.
        let v = result(step(&h, &mut first, vec![HttpReply::default()]));
        assert!(v["apps"][0]["error"].as_str().unwrap().contains("didn't answer in time"), "{v}");
        let mut third = search();
        assert!(fetches(step(&h, &mut third, vec![]))[0].url.contains("oauth2.googleapis.com/token"), "the first let go");

        // A refused refresh token does mean reconnecting.
        let v = result(step(&h, &mut third, vec![HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() }]));
        assert!(v["apps"][0]["error"].as_str().unwrap().contains("connect it again"), "{v}");
    }
}

// ---------------------------------------------------------------------------
// Single sign-on. The tests play the host and the identity provider: they run each job's steps
// with canned answers, and make the ID tokens the provider's token endpoint would send.

mod sso {
    use super::*;
    use dumbslab_core::connect::{self, Finish, HttpCall, HttpReply, Job, Step};

    const TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    const OKTA: &str = "https://acme.okta.test";

    fn ms_issuer() -> String {
        format!("https://login.microsoftonline.com/{TENANT}/v2.0")
    }

    fn job_of(r: &Res) -> Job {
        r.effects
            .iter()
            .find_map(|e| match e {
                Effect::Connect(j) => Some(j.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("a job, but got {} {:?}", r.status, r.header("location")))
    }

    /// Runs a job, answering each step's requests with `answer`. Returns how it finished and every
    /// request it made.
    fn drive(h: &H, mut job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Finish, Vec<HttpCall>) {
        let mut replies = vec![];
        let mut sent = vec![];
        for _ in 0..connect::MAX_STEPS {
            let (step, next) = h
                .store
                .with_tx(|db| {
                    let step = connect::step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now());
                    let ok = step.is_ok();
                    ((step, job.clone()), ok)
                })
                .unwrap();
            job = next;
            match step.unwrap() {
                Step::Done(f) => return (f, sent),
                Step::Fetch(calls) => {
                    replies = calls.iter().map(answer).collect();
                    sent.extend(calls);
                }
            }
        }
        panic!("job didn't finish");
    }

    fn ok(body: Value) -> HttpReply {
        HttpReply { status: 200, body: body.to_string() }
    }

    fn discovery(issuer: &str) -> Value {
        let base = issuer.trim_end_matches('/');
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "userinfo_endpoint": format!("{base}/userinfo"),
            // Slack takes the client secret in the form only.
            "token_endpoint_auth_methods_supported": if issuer == "https://slack.com" { json!(["client_secret_post"]) } else { json!(["client_secret_basic", "client_secret_post"]) },
        })
    }

    /// An ID token as a provider signs it. Its signature isn't checked: it comes from the token endpoint over TLS.
    fn jwt(claims: &Value) -> String {
        let part = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        format!("{}.{}.c2lnbmF0dXJl", part(json!({ "alg": "RS256", "kid": "k1" })), part(claims.clone()))
    }

    fn claims(issuer: &str, sub: &str, email: &str, extra: Value) -> Value {
        let now = chrono::Utc::now().timestamp();
        let mut c =
            json!({ "iss": issuer, "aud": "app-id", "sub": sub, "email": email, "exp": now + 300, "iat": now, "name": "Mo Member" });
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    }

    /// Where a request finally sent the browser, and the cookies it set.
    struct Landing {
        location: String,
        cookies: Vec<String>,
    }

    impl Landing {
        fn session(&self) -> Option<Auth> {
            self.cookies
                .iter()
                .find_map(|c| c.strip_prefix("dumbslab_session="))
                .map(|c| c.split(';').next().unwrap())
                .filter(|v| !v.is_empty())
                .map(|v| Auth::Cookie(v.to_string()))
        }
        /// What went wrong. Redirects carry a known code and nothing else, so nobody can put their
        /// own words on the sign-in page, and nothing from the provider ends up there.
        fn error(&self) -> String {
            let q = query_of(&self.location);
            let Some(code) = q.get("sso_error") else { return String::new() };
            let known: Vec<&str> = dumbslab_core::sso::Problem::ALL.iter().map(|p| p.code()).collect();
            assert!(known.contains(&code.as_str()), "unknown code `{code}` in {}", self.location);
            assert!(q.keys().all(|k| k == "sso_error" || k == "next"), "only a code and where to go: {}", self.location);
            code.clone()
        }
    }

    /// The answer a request gets once its job (if any) finished.
    fn land(r: &Res, finish: Option<Finish>) -> Landing {
        let original = dumbslab_core::Response { status: r.status, headers: r.headers.clone(), body: r.bytes.clone() };
        let resp = match finish {
            Some(f) => connect::respond(original, f),
            None => original,
        };
        let header = |n: &str| resp.headers.iter().filter(|(k, _)| k == n).map(|(_, v)| v.clone()).collect::<Vec<_>>();
        assert!((300..400).contains(&resp.status), "a redirect, not {} {}", resp.status, String::from_utf8_lossy(&resp.body));
        Landing { location: header("location").into_iter().next().unwrap_or_default(), cookies: header("set-cookie") }
    }

    /// Saves single sign-on settings as `admin`, answering the check with the issuer's discovery document.
    fn set_up(h: &H, admin: &Auth, body: Value, issuer: &str) -> Value {
        let r = h.call("PATCH", "/api/v1/sso", Some(body), admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(h, job_of(&r), &|_| ok(discovery(issuer)));
        assert_eq!(sent[0].url, format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/')));
        match finish {
            Finish::Fill(v) => connect::fill(r.body.clone(), Ok(v)).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    /// A workspace with a connector key, and its admin (ada@acme.test).
    fn workspace() -> (H, Auth) {
        let mut h = H::new();
        let (admin, _) = h.setup();
        h.cfg.connectors.key = Some("connector-key".into());
        (h, admin)
    }

    fn okta(h: &H, admin: &Auth, extra: Value) {
        let mut body = json!({ "provider": "okta", "issuer": OKTA, "client_id": "app-id", "client_secret": "shh-client-secret",
            "allowed_domains": ["acme.test"], "enabled": true });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let v = set_up(h, admin, body, OKTA);
        assert_eq!((v["check"]["ok"].as_bool(), v["active"].as_bool()), (Some(true), Some(true)), "{v}");
    }

    /// A sign-in under way: the provider's sign-in URL's query, and the cookie the browser got.
    struct Started {
        query: std::collections::HashMap<String, String>,
        url: String,
        cookie: String,
    }

    fn start(h: &H, issuer: &str) -> Started {
        let r = h.call("GET", "/sso/start?next=%2Fp%2Fabc", None, &Auth::None);
        let (finish, sent) = drive(h, job_of(&r), &|_| ok(discovery(issuer)));
        assert_eq!(sent.len(), 1);
        let landing = land(&r, Some(finish));
        let cookie = landing.cookies.iter().find_map(|c| c.strip_prefix("dumbslab_sso=")).expect("the browser's cookie");
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Path=/sso"), "{cookie}");
        Started { query: query_of(&landing.location), url: landing.location.clone(), cookie: cookie.split(';').next().unwrap().to_string() }
    }

    fn callback_request(query: &str, cookies: &[String]) -> Request {
        Request {
            method: "GET".into(),
            path: "/sso/callback".into(),
            query: query.into(),
            headers: if cookies.is_empty() { vec![] } else { vec![("cookie".into(), cookies.join("; "))] },
            origin: "https://kb.test".into(),
            ..Default::default()
        }
    }

    /// The provider sends the browser back with a code; its token endpoint answers with `id_token`
    /// (the started sign-in's nonce is filled in unless the claims have one).
    fn come_back(h: &H, s: &Started, mut id_claims: Value, token: &dyn Fn(&HttpCall, &str) -> HttpReply) -> (Landing, Vec<HttpCall>) {
        if id_claims.get("nonce").is_none() {
            id_claims["nonce"] = json!(s.query["nonce"]);
        }
        let q = format!("code=the-code&state={}", urlencoding::encode(&s.query["state"]));
        let r = h.send(&callback_request(&q, &[format!("dumbslab_sso={}", s.cookie)]));
        if r.effects.is_empty() {
            return (land(&r, None), vec![]);
        }
        let jwt = jwt(&id_claims);
        let (finish, sent) = drive(h, job_of(&r), &|c| token(c, &jwt));
        (land(&r, Some(finish)), sent)
    }

    /// The token endpoint, answering with the ID token.
    fn tokens(_: &HttpCall, jwt: &str) -> HttpReply {
        ok(json!({ "access_token": "provider-access-token", "token_type": "Bearer", "id_token": jwt }))
    }

    fn sign_in_with(h: &H, issuer: &str, id_claims: Value) -> Landing {
        let s = start(h, issuer);
        come_back(h, &s, id_claims, &tokens).0
    }

    fn me(h: &H, auth: &Auth) -> Value {
        h.ok("GET", "/api/v1/me", None, auth)["user"].clone()
    }

    #[test]
    fn settings_are_for_admins_and_never_show_the_secret() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        assert_eq!(h.call("GET", "/api/v1/sso", None, &mo).status, 403);
        assert_eq!(h.call("PATCH", "/api/v1/sso", Some(json!({ "provider": "okta" })), &mo).status, 403);

        // Without a connector key there's nowhere safe for a client secret, so it's off.
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!((s["available"].as_bool(), s["active"].as_bool()), (Some(false), Some(false)));
        assert_eq!(s["redirect_uri"], "https://kb.test/sso/callback");
        let body = json!({ "provider": "okta", "issuer": OKTA, "client_id": "app-id", "client_secret": "shh-client-secret" });
        assert_eq!(h.call("PATCH", "/api/v1/sso", Some(body), &admin).status, 503);
        assert!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"].is_null());

        h.cfg.connectors.key = Some("connector-key".into());
        let bad = |body: Value| {
            let r = h.call("PATCH", "/api/v1/sso", Some(body), &admin);
            assert_eq!(r.status, 400, "{}", r.body);
            r.body["error"]["message"].as_str().unwrap().to_string()
        };
        assert!(bad(json!({ "provider": "okta", "enabled": true })).contains("`issuer`, `client_id`, `client_secret`"));
        assert!(bad(json!({ "provider": "okta", "issuer": "http://acme.okta.test" })).contains("https"));
        assert!(bad(json!({ "provider": "microsoft", "tenant": "common" })).contains("GUID"));
        assert!(bad(json!({ "provider": "microsoft", "tenant": "contoso.onmicrosoft.com" })).contains("GUID"));
        assert!(bad(json!({ "provider": "google", "client_id": "x", "client_secret": "y", "enabled": true })).contains("allowed_domains"));
        assert!(bad(json!({ "provider": "okta", "allowed_domains": ["not a domain"] })).contains("domain"));

        let r = h.call(
            "PATCH",
            "/api/v1/sso",
            Some(json!({ "provider": "okta", "issuer": OKTA, "client_id": "app-id", "client_secret": "shh-client-secret",
                "allowed_domains": ["@Acme.TEST", "acme.test"], "enabled": true })),
            &admin,
        );
        assert!(!r.body.to_string().contains("shh-client-secret"));
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery(OKTA)));
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        assert_eq!(
            (v["check"]["ok"].as_bool(), v["active"].as_bool(), v["client_secret_set"].as_bool()),
            (Some(true), Some(true), Some(true))
        );
        assert_eq!(v["allowed_domains"], json!(["acme.test"]));
        assert_eq!(v["check"]["authorization_endpoint"], format!("{OKTA}/authorize"));
        // The secret is stored encrypted and never comes back.
        let stored: String = h
            .store
            .with_tx(|db| (db.one("SELECT value FROM settings WHERE key = 'sso'", &[]).unwrap().unwrap().str("value"), true))
            .unwrap();
        assert!(!stored.contains("shh-client-secret"), "{stored}");
        for shown in
            [v.to_string(), h.ok("GET", "/api/v1/sso", None, &admin).to_string(), h.ok("GET", "/api/v1/export", None, &admin).to_string()]
        {
            assert!(!shown.contains("shh-client-secret") && !shown.contains(&stored), "{shown}");
        }
        // The sign-in page learns only the button.
        let state = h.ok("GET", "/api/v1/auth/state", None, &Auth::None);
        assert_eq!(state["sso"], json!({ "name": "Okta", "url": "https://kb.test/sso/start", "required": false }));

        // A discovery document naming another issuer fails the check.
        let r = h.call("PATCH", "/api/v1/sso", Some(json!({ "auto_provision": false })), &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery("https://evil.test")));
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        assert_eq!(v["check"]["ok"], false);
        assert!(v["check"]["error"].as_str().unwrap().contains("match exactly"), "{v}");
        // So does one that isn't there.
        let r = h.call("PATCH", "/api/v1/sso", Some(json!({ "auto_provision": false })), &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_| HttpReply { status: 404, body: "not found".into() });
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        assert!(v["check"]["error"].as_str().unwrap().contains("HTTP 404"), "{v}");

        // A secret belongs to its app: another client ID needs its own.
        assert!(bad(json!({ "client_id": "another-app" })).contains("client_secret"));
        let v = set_up(&h, &admin, json!({ "client_id": "another-app", "enabled": false }), OKTA);
        assert_eq!((v["client_secret_set"].as_bool(), v["active"].as_bool()), (Some(false), Some(false)));
        assert!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"].is_null());
        // Settings changes are in the admins' activity, without the secret.
        let activity = h.ok("GET", "/api/v1/activity", None, &admin).to_string();
        assert!(activity.contains("sso.updated") && !activity.contains("shh-client-secret"));
    }

    #[test]
    fn signing_in_with_each_provider() {
        let cases = [
            (
                json!({ "provider": "google", "allowed_domains": ["acme.test"] }),
                "https://accounts.google.com".to_string(),
                json!({ "email_verified": true, "hd": "acme.test" }),
                "Google",
            ),
            (
                json!({ "provider": "microsoft", "tenant": TENANT.to_uppercase(), "allowed_domains": ["acme.test"] }),
                ms_issuer(),
                json!({ "tid": TENANT, "xms_edov": true }),
                "Microsoft",
            ),
            (
                json!({ "provider": "okta", "issuer": OKTA, "allowed_domains": ["acme.test"] }),
                OKTA.to_string(),
                json!({ "email_verified": true }),
                "Okta",
            ),
            (
                json!({ "provider": "onelogin", "issuer": "https://acme.onelogin.test/oidc/2", "allowed_domains": ["acme.test"] }),
                "https://acme.onelogin.test/oidc/2".to_string(),
                json!({ "email_verified": "true" }),
                "OneLogin",
            ),
            (
                json!({ "provider": "slack", "team": "T0ACME", "allowed_domains": ["acme.test"] }),
                "https://slack.com".to_string(),
                json!({ "email_verified": true, "https://slack.com/team_id": "T0ACME" }),
                "Slack",
            ),
            (
                json!({ "provider": "oidc", "issuer": "https://id.acme.test/", "label": "Acme ID", "allowed_domains": ["acme.test"] }),
                "https://id.acme.test/".to_string(),
                json!({ "email_verified": true }),
                "Acme ID",
            ),
        ];
        for (mut body, issuer, extra, name) in cases {
            let (h, admin) = workspace();
            h.user(&admin, "mo@acme.test", "Mo", "member");
            body["client_id"] = json!("app-id");
            body["client_secret"] = json!("shh-client-secret");
            body["enabled"] = json!(true);
            let v = set_up(&h, &admin, body, &issuer);
            assert_eq!(
                (v["check"]["ok"].as_bool(), v["active"].as_bool(), v["issuer"].as_str()),
                (Some(true), Some(true), Some(issuer.as_str())),
                "{name}: {v}"
            );
            assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"]["name"], name);

            let s = start(&h, &issuer);
            assert!(s.url.starts_with(&format!("{}/authorize?", issuer.trim_end_matches('/'))), "{name}: {}", s.url);
            let q = &s.query;
            assert_eq!((q["response_type"].as_str(), q["client_id"].as_str()), ("code", "app-id"), "{name}");
            assert_eq!((q["redirect_uri"].as_str(), q["scope"].as_str()), ("https://kb.test/sso/callback", "openid email profile"));
            assert_eq!(q["code_challenge_method"], "S256");
            assert!(q["state"].len() >= 32 && q["nonce"].len() >= 32 && q["code_challenge"].len() == 43, "{name}: {q:?}");
            match name {
                "Google" => assert_eq!((q["hd"].as_str(), q["prompt"].as_str()), ("acme.test", "select_account")),
                "Slack" => assert_eq!(q["team"], "T0ACME"),
                _ => {}
            }

            let (landing, sent) = come_back(&h, &s, claims(&issuer, "sub-mo", "Mo@acme.test", extra.clone()), &tokens);
            assert_eq!(landing.location, "https://kb.test/p/abc", "{name}: {}", landing.error());
            let session = landing.session().unwrap_or_else(|| panic!("{name}: a session"));
            assert!(landing.cookies.iter().any(|c| c.starts_with("dumbslab_session=") && c.contains("Secure") && c.contains("HttpOnly")));
            assert!(landing.cookies.iter().any(|c| c.starts_with("dumbslab_sso=;")), "the browser cookie is cleared");
            assert_eq!(me(&h, &session)["email"], "mo@acme.test", "{name}");

            // The code went to the token endpoint with the PKCE verifier and the client secret.
            let exchange = &sent[0];
            assert_eq!(exchange.url, format!("{}/token", issuer.trim_end_matches('/')));
            let form = query_of(&format!("?{}", exchange.body.clone().unwrap()));
            assert_eq!((form["grant_type"].as_str(), form["code"].as_str()), ("authorization_code", "the-code"));
            assert_eq!(form["redirect_uri"], "https://kb.test/sso/callback");
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes()));
            assert_eq!(challenge, q["code_challenge"], "{name}");
            let basic = exchange.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone());
            if name == "Slack" {
                assert_eq!((form["client_id"].as_str(), form["client_secret"].as_str(), basic), ("app-id", "shh-client-secret", None));
            } else {
                let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("app-id:shh-client-secret"));
                assert_eq!(basic.as_deref(), Some(expected.as_str()), "{name}");
                assert!(!form.contains_key("client_secret"));
            }

            // Linked by subject now: the next sign-in finds Mo whatever email the provider gives.
            let again = sign_in_with(
                &h,
                &issuer,
                claims(
                    &issuer,
                    "sub-mo",
                    "renamed@elsewhere.test",
                    json!({ "tid": TENANT, "hd": "acme.test", "https://slack.com/team_id": "T0ACME" }),
                ),
            );
            assert_eq!(me(&h, &again.session().unwrap_or_else(|| panic!("{name}: {}", again.error())))["email"], "mo@acme.test");
            let linked = h.ok("GET", "/api/v1/sso/identities?user=all", None, &admin);
            assert_eq!(linked["items"].as_array().unwrap().len(), 1, "{name}");
            assert_eq!(linked["items"][0]["email"], "Mo@acme.test");
        }
    }

    #[test]
    fn tokens_that_dont_check_out_are_refused() {
        let (h, admin) = workspace();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({}));
        let now = chrono::Utc::now().timestamp();
        let verified = || json!({ "email_verified": true });
        let no_session = |l: &Landing| l.session().is_none() && l.location.starts_with("https://kb.test/login?sso_error=");

        for (claim, value) in [
            ("aud", json!("someone-elses-app")),
            ("azp", json!("someone-elses-app")),
            ("iss", json!("https://evil.test")),
            ("exp", json!(now - 600)),
            ("iat", json!(now + 7200)),
            ("nonce", json!("not-this-sign-ins-nonce")),
        ] {
            let mut c = claims(OKTA, "sub-mo", "mo@acme.test", verified());
            c[claim] = value;
            let landing = sign_in_with(&h, OKTA, c);
            assert!(no_session(&landing), "{claim}: {}", landing.location);
            assert_eq!(landing.error(), "invalid_token", "{claim}");
            assert!(landing.location.contains("next=%2Fp%2Fabc"), "keeps where they were going");
        }

        // A discovery document naming another issuer: no sign-in starts.
        let r = h.call("GET", "/sso/start", None, &Auth::None);
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery("https://evil.test")));
        let landing = land(&r, Some(finish));
        assert_eq!(landing.error(), "provider_error");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sso_requests"), 0);
        // No answer at all: the request's own fallback, not an error page.
        let r = h.call("GET", "/sso/start", None, &Auth::None);
        let landing = land(&r, Some(Finish::Fail(dumbslab_core::ApiError::internal("the host gave up"))));
        assert_eq!(landing.error(), "failed");

        // Each sign-in link works once.
        let s = start(&h, OKTA);
        let (first, _) = come_back(&h, &s, claims(OKTA, "sub-mo", "mo@acme.test", verified()), &tokens);
        assert!(first.session().is_some(), "{}", first.error());
        let (replayed, _) = come_back(&h, &s, claims(OKTA, "sub-mo", "mo@acme.test", verified()), &tokens);
        assert!(no_session(&replayed) && replayed.error() == "expired", "{}", replayed.location);

        // Only the browser that started can finish (no signing someone in to the attacker's account).
        for cookies in [vec![], vec!["dumbslab_sso=someone-elses".to_string()]] {
            let s = start(&h, OKTA);
            let q = format!("code=attackers-code&state={}", urlencoding::encode(&s.query["state"]));
            let r = h.send(&callback_request(&q, &cookies));
            assert!(r.effects.is_empty());
            assert_eq!(land(&r, None).error(), "other_browser");
        }

        // Too slow.
        let s = start(&h, OKTA);
        let past = dumbslab_core::util::ts(chrono::Utc::now() - chrono::Duration::minutes(16));
        h.store.with_tx(|db| (db.execute("UPDATE sso_requests SET created_at = ?", &dumbslab_core::params![past]), true)).unwrap().unwrap();
        let (late, _) = come_back(&h, &s, claims(OKTA, "sub-mo", "mo@acme.test", verified()), &tokens);
        assert_eq!(late.error(), "expired");

        // The provider saying no, or refusing the code: a readable message, nothing raw.
        let s = start(&h, OKTA);
        let q = format!("error=access_denied&error_description=User+cancelled&state={}", urlencoding::encode(&s.query["state"]));
        let r = h.send(&callback_request(&q, &[format!("dumbslab_sso={}", s.cookie)]));
        assert_eq!(land(&r, None).error(), "denied");
        // Any other error, with whatever text the provider (or someone) puts in the link, is just that: an error.
        let s = start(&h, OKTA);
        let q = format!(
            "error=server_error&error_description=Your+account+is+locked.+Call+555-0100&state={}",
            urlencoding::encode(&s.query["state"])
        );
        let landing = land(&h.send(&callback_request(&q, &[format!("dumbslab_sso={}", s.cookie)])), None);
        assert_eq!(landing.error(), "provider_error");
        assert!(!landing.location.contains("locked") && !landing.location.contains("555"), "{}", landing.location);
        let s = start(&h, OKTA);
        let refused = |_: &HttpCall, _: &str| HttpReply {
            status: 400,
            body: json!({ "error": "invalid_grant", "error_description": "code expired", "access_token": "leaked?" }).to_string(),
        };
        let (landing, _) = come_back(&h, &s, claims(OKTA, "sub-mo", "mo@acme.test", verified()), &refused);
        assert_eq!(landing.error(), "provider_error");
        assert!(!landing.location.contains("invalid_grant") && !landing.location.contains("leaked"), "{}", landing.location);
        // An answer that isn't a signed ID token.
        let s = start(&h, OKTA);
        let unsigned = |_: &HttpCall, _: &str| ok(json!({ "access_token": "at", "id_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." }));
        let (landing, _) = come_back(&h, &s, json!({}), &unsigned);
        assert_eq!(landing.error(), "invalid_token");

        // Settings changing mid-sign-in.
        let s = start(&h, OKTA);
        set_up(&h, &admin, json!({ "issuer": "https://acme-new.okta.test" }), "https://acme-new.okta.test");
        let (landing, _) = come_back(&h, &s, claims(OKTA, "sub-mo", "mo@acme.test", verified()), &tokens);
        assert_eq!(landing.error(), "expired");
    }

    #[test]
    fn first_sign_ins_match_only_vouched_emails_at_allowed_domains() {
        let (h, admin) = workspace();
        let (mo_id, _) = h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({}));
        let refused = |c: Value, why: &str| {
            let landing = sign_in_with(&h, OKTA, c);
            assert!(landing.session().is_none(), "{why}");
            assert_eq!(landing.error(), why);
        };
        refused(claims(OKTA, "sub-mo", "mo@acme.test", json!({ "email_verified": false })), "unverified_email");
        refused(claims(OKTA, "sub-mo", "mo@acme.test", json!({})), "unverified_email");
        refused(claims(OKTA, "sub-mo", "mo@other.test", json!({ "email_verified": true })), "domain_not_allowed");
        refused(claims(OKTA, "sub-new", "new@acme.test", json!({ "email_verified": true })), "no_account");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sso_identities"), 0);

        // Some providers give the email in the userinfo answer only; it must be about the same account.
        let s = start(&h, OKTA);
        let mut c = claims(OKTA, "sub-mo", "", json!({}));
        c.as_object_mut().unwrap().remove("email");
        let provider = |call: &HttpCall, jwt: &str| {
            if call.url.ends_with("/userinfo") {
                assert!(call.headers.contains(&("authorization".into(), "Bearer provider-access-token".into())));
                ok(json!({ "sub": "sub-mo", "email": "mo@acme.test", "email_verified": true }))
            } else {
                tokens(call, jwt)
            }
        };
        let (landing, sent) = come_back(&h, &s, c.clone(), &provider);
        assert_eq!(sent.len(), 2);
        assert_eq!(me(&h, &landing.session().unwrap_or_else(|| panic!("{}", landing.error())))["id"], mo_id.as_str());
        // Linking by email is a new way into Mo's account: the admins' activity log says so.
        assert_eq!(links_logged(&h, &admin), vec![(mo_id.clone(), "email".to_string())]);
        h.store.with_tx(|db| (db.execute("DELETE FROM sso_identities", &[]), true)).unwrap().unwrap();
        let s = start(&h, OKTA);
        let someone_else = |call: &HttpCall, jwt: &str| {
            if call.url.ends_with("/userinfo") {
                ok(json!({ "sub": "sub-other", "email": "mo@acme.test", "email_verified": true }))
            } else {
                tokens(call, jwt)
            }
        };
        let (landing, _) = come_back(&h, &s, c, &someone_else);
        assert_eq!(landing.error(), "unverified_email");

        // Deactivated people can't sign in, linked or not.
        assert!(sign_in_with(&h, OKTA, claims(OKTA, "sub-mo", "mo@acme.test", json!({ "email_verified": true }))).session().is_some());
        h.ok("PATCH", &format!("/api/v1/users/{mo_id}"), Some(json!({ "deactivated": true })), &admin);
        refused(claims(OKTA, "sub-mo", "mo@acme.test", json!({ "email_verified": true })), "deactivated");
        refused(claims(OKTA, "sub-mo-2", "mo@acme.test", json!({ "email_verified": true })), "deactivated");
        // Nor bots.
        h.ok("POST", "/api/v1/users", Some(json!({ "email": "bot@acme.test", "name": "Bot", "is_bot": true })), &admin);
        refused(claims(OKTA, "sub-bot", "bot@acme.test", json!({ "email_verified": true })), "bot");
        // An address already linked to another account at this provider isn't taken over.
        h.ok("PATCH", &format!("/api/v1/users/{mo_id}"), Some(json!({ "deactivated": false })), &admin);
        refused(claims(OKTA, "sub-mo-2", "mo@acme.test", json!({ "email_verified": true })), "email_linked");

        // Auto-provisioning: people the provider vouches for join as members.
        set_up(&h, &admin, json!({ "auto_provision": true }), OKTA);
        let landing =
            sign_in_with(&h, OKTA, claims(OKTA, "sub-new", "New@Acme.test", json!({ "email_verified": true, "name": "Nia New" })));
        let new = me(&h, &landing.session().unwrap_or_else(|| panic!("{}", landing.error())));
        assert_eq!(
            (new["email"].as_str(), new["name"].as_str(), new["role"].as_str()),
            (Some("new@acme.test"), Some("Nia New"), Some("member"))
        );
        let activity = h.ok("GET", "/api/v1/activity", None, &admin).to_string();
        assert!(activity.contains("joined by signing in with Okta"), "{activity}");
        assert_eq!(
            links_logged(&h, &admin).last().map(|(who, how)| (who.as_str(), how.as_str())),
            Some((new["id"].as_str().unwrap(), "provisioned"))
        );
        // Still only from allowed domains, with verified emails.
        refused(claims(OKTA, "sub-x", "x@other.test", json!({ "email_verified": true })), "domain_not_allowed");
        refused(claims(OKTA, "sub-y", "y@acme.test", json!({ "email_verified": false })), "unverified_email");
    }

    #[test]
    fn google_and_slack_sign_ins_stay_inside_the_organization() {
        let (h, admin) = workspace();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let google = "https://accounts.google.com";
        set_up(
            &h,
            &admin,
            json!({ "provider": "google", "allowed_domains": ["acme.test"], "client_id": "app-id", "client_secret": "s", "enabled": true }),
            google,
        );
        // A personal Google account (no hosted domain), or another company's, never signs in.
        for extra in [json!({ "email_verified": true }), json!({ "email_verified": true, "hd": "other.test" })] {
            let landing = sign_in_with(&h, google, claims(google, "g-mo", "mo@acme.test", extra));
            assert!(landing.session().is_none() && landing.error() == "not_in_org", "{}", landing.location);
        }
        // Google's ID tokens may name the issuer without its scheme.
        let landing = sign_in_with(
            &h,
            google,
            claims("accounts.google.com", "g-mo", "mo@acme.test", json!({ "email_verified": true, "hd": "acme.test" })),
        );
        assert!(landing.session().is_some(), "{}", landing.error());

        let slack = "https://slack.com";
        set_up(
            &h,
            &admin,
            json!({ "provider": "slack", "team": "t0acme", "client_id": "app-id", "client_secret": "s", "enabled": true }),
            slack,
        );
        let landing = sign_in_with(
            &h,
            slack,
            claims(slack, "U1", "mo@acme.test", json!({ "email_verified": true, "https://slack.com/team_id": "T0OTHER" })),
        );
        assert_eq!(landing.error(), "not_in_org");
    }

    #[test]
    fn microsoft_needs_xms_edov_or_a_linked_account() {
        let (h, admin) = workspace();
        let (mo_id, mo_token) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let issuer = ms_issuer();
        let v = set_up(
            &h,
            &admin,
            json!({ "provider": "microsoft", "tenant": TENANT, "allowed_domains": ["acme.test"], "client_id": "app-id", "client_secret": "s", "enabled": true }),
            &issuer,
        );
        assert_eq!(v["issuer"], issuer);
        // `email` alone, even "verified" and matching the UPN, isn't proof of the address (nOAuth).
        let unproven = json!({ "tid": TENANT, "email_verified": true, "upn": "mo@acme.test", "preferred_username": "mo@acme.test" });
        let landing = sign_in_with(&h, &issuer, claims(&issuer, "ms-mo", "mo@acme.test", unproven.clone()));
        assert!(landing.session().is_none() && landing.error() == "unverified_email", "{}", landing.location);
        // Another directory's account, even with xms_edov.
        let landing = sign_in_with(
            &h,
            &issuer,
            claims(&issuer, "ms-mo", "mo@acme.test", json!({ "tid": "00000000-0000-0000-0000-000000000000", "xms_edov": true })),
        );
        assert_eq!(landing.error(), "not_in_org");

        // Mo links their Microsoft account while signed in with a password...
        let mo = sign_in(&h, "mo@acme.test", "password123");
        assert_eq!(h.call("POST", "/api/v1/me/sso", None, &mo_token).status, 403, "only from a signed-in browser");
        let r = h.call("POST", "/api/v1/me/sso", None, &mo);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery(&issuer)));
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        let q = query_of(v["authorize_url"].as_str().unwrap());
        let link = |auth: &Auth, sub: &str| {
            let Auth::Cookie(session) = auth else { unreachable!() };
            let r = h.send(&callback_request(
                &format!("code=c&state={}", urlencoding::encode(&q["state"])),
                &[format!("dumbslab_session={session}")],
            ));
            if r.effects.is_empty() {
                return land(&r, None);
            }
            let id = jwt(&claims(&issuer, sub, "mo@acme.test", json!({ "tid": TENANT, "nonce": q["nonce"] })));
            let (finish, _) = drive(&h, job_of(&r), &|c| tokens(c, &id));
            land(&r, Some(finish))
        };
        // ...in their own browser only.
        let landing = link(&admin, "ms-mo");
        assert_eq!(landing.location, "https://kb.test/settings/profile?sso_error=other_session");
        assert_eq!(landing.error(), "other_session");
        let r = h.call("POST", "/api/v1/me/sso", None, &mo);
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery(&issuer)));
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        let q2 = query_of(v["authorize_url"].as_str().unwrap());
        let r = h.send(&callback_request(
            &format!("code=c&state={}", urlencoding::encode(&q2["state"])),
            &[{
                let Auth::Cookie(c) = &mo else { unreachable!() };
                format!("dumbslab_session={c}")
            }],
        ));
        let id = jwt(&claims(&issuer, "ms-mo", "mo@acme.test", json!({ "tid": TENANT, "nonce": q2["nonce"] })));
        let (finish, _) = drive(&h, job_of(&r), &|c| tokens(c, &id));
        let landing = land(&r, Some(finish));
        assert_eq!(landing.location, "https://kb.test/settings/profile?sso_linked=1");
        assert!(landing.session().is_none(), "linking doesn't start another session");
        let mine = h.ok("GET", "/api/v1/sso/identities", None, &mo);
        assert_eq!((mine["items"][0]["current"].as_bool(), mine["items"][0]["user"]["id"].as_str()), (Some(true), Some(mo_id.as_str())));

        // Now Mo signs in with Microsoft, no xms_edov needed.
        let landing = sign_in_with(&h, &issuer, claims(&issuer, "ms-mo", "mo@acme.test", unproven.clone()));
        assert_eq!(me(&h, &landing.session().unwrap_or_else(|| panic!("{}", landing.error())))["id"], mo_id.as_str());

        // Nobody else can claim that Microsoft account.
        let ada = sign_in(&h, "ada@acme.test", "correct horse");
        let r = h.call("POST", "/api/v1/me/sso", None, &ada);
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery(&issuer)));
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        let q3 = query_of(v["authorize_url"].as_str().unwrap());
        let Auth::Cookie(ada_session) = &ada else { unreachable!() };
        let r = h.send(&callback_request(
            &format!("code=c&state={}", urlencoding::encode(&q3["state"])),
            &[format!("dumbslab_session={ada_session}")],
        ));
        let id = jwt(&claims(&issuer, "ms-mo", "mo@acme.test", json!({ "tid": TENANT, "nonce": q3["nonce"] })));
        let (finish, _) = drive(&h, job_of(&r), &|c| tokens(c, &id));
        assert_eq!(land(&r, Some(finish)).error(), "already_linked");

        // Unlinking (yours, or anyone's for admins) stops it signing in.
        let id = mine["items"][0]["id"].as_str().unwrap().to_string();
        let (_, other) = h.user(&admin, "zed@acme.test", "Zed", "member");
        assert_eq!(h.call("DELETE", &format!("/api/v1/sso/identities/{id}"), None, &other).status, 403);
        h.ok("DELETE", &format!("/api/v1/sso/identities/{id}"), None, &mo);
        let landing = sign_in_with(&h, &issuer, claims(&issuer, "ms-mo", "mo@acme.test", unproven));
        assert!(landing.session().is_none());
        // With xms_edov, a first sign-in matches the email.
        let landing = sign_in_with(&h, &issuer, claims(&issuer, "ms-mo", "mo@acme.test", json!({ "tid": TENANT, "xms_edov": true })));
        assert_eq!(me(&h, &landing.session().unwrap_or_else(|| panic!("{}", landing.error())))["id"], mo_id.as_str());
    }

    #[test]
    fn requiring_sso_keeps_passwords_for_admins_only() {
        let (h, admin) = workspace();
        let (_, mo_token) = h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({ "require_sso": true }));
        assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"]["required"], true);
        let login = |email: &str, password: &str| {
            h.call("POST", "/api/v1/auth/login", Some(json!({ "email": email, "password": password })), &Auth::None)
        };
        let r = login("mo@acme.test", "password123");
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (403, Some("sso_required")), "{}", r.body);
        assert!(r.header("set-cookie").is_none());
        assert!(r.body["error"]["message"].as_str().unwrap().contains("Sign in with Okta"));
        // A wrong password still says only that.
        assert_eq!(login("mo@acme.test", "wrong password").status, 401);
        // Admins keep their password, in case the provider fails.
        assert_eq!(login("ada@acme.test", "correct horse").status, 200);
        // Tokens (scripts, agents, MCP) are unaffected.
        assert_eq!(h.ok("GET", "/api/v1/me", None, &mo_token)["user"]["email"], "mo@acme.test");
        // Mo signs in with Okta instead.
        let landing = sign_in_with(&h, OKTA, claims(OKTA, "sub-mo", "mo@acme.test", json!({ "email_verified": true })));
        assert!(landing.session().is_some(), "{}", landing.error());
        // If single sign-on is turned off, passwords work again: nobody is locked out.
        set_up(&h, &admin, json!({ "enabled": false }), OKTA);
        assert_eq!(login("mo@acme.test", "password123").status, 200);
        let r = h.call("GET", "/sso/start", None, &Auth::None);
        assert!(r.effects.is_empty() && land(&r, None).error() == "not_configured");
    }

    /// The `sso.linked` events in the admins' activity log, oldest first: who, and how it was matched.
    fn links_logged(h: &H, admin: &Auth) -> Vec<(String, String)> {
        let activity = h.ok("GET", "/api/v1/activity?limit=100", None, admin);
        let mut links: Vec<(String, String)> = activity["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["event"] == "sso.linked")
            .map(|e| {
                (
                    e["actor"]["id"].as_str().unwrap_or_default().to_string(),
                    e["data"]["matched_by"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        links.reverse();
        links
    }

    #[test]
    fn links_finish_only_in_the_session_that_started_them() {
        let (h, admin) = workspace();
        let (mo_id, _) = h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({}));
        let session = |auth: &Auth| match auth {
            Auth::Cookie(c) => format!("dumbslab_session={c}"),
            _ => unreachable!(),
        };
        // Starts linking in `auth`'s session; returns the provider's sign-in URL's query.
        let start_link = |auth: &Auth| {
            let r = h.call("POST", "/api/v1/me/sso", None, auth);
            assert_eq!(r.status, 200, "{}", r.body);
            let (finish, _) = drive(&h, job_of(&r), &|_| ok(discovery(OKTA)));
            let Finish::Fill(v) = finish else { panic!("{finish:?}") };
            query_of(v["authorize_url"].as_str().unwrap())
        };
        // The provider sends the browser, signed in as `auth`, back.
        let come_back_to = |auth: &Auth, q: &std::collections::HashMap<String, String>| {
            h.send(&callback_request(&format!("code=c&state={}", urlencoding::encode(&q["state"])), &[session(auth)]))
        };
        let answer = |r: &Res, q: &std::collections::HashMap<String, String>| {
            if r.effects.is_empty() {
                return land(r, None);
            }
            let id = jwt(&claims(OKTA, "okta-mo", "mo@acme.test", json!({ "nonce": q["nonce"] })));
            let (finish, _) = drive(&h, job_of(r), &|c| tokens(c, &id));
            land(r, Some(finish))
        };
        let linked = || count(&h, "SELECT COUNT(*) FROM sso_identities");
        let sign_out = |auth: &Auth| assert_eq!(h.call("POST", "/api/v1/auth/logout", None, auth).status, 200);

        // Started in session A, which is then signed out (say it was stolen and revoked):
        // finishing in Mo's other session B is refused, so the pending link dies with A.
        let a = sign_in(&h, "mo@acme.test", "password123");
        let b = sign_in(&h, "mo@acme.test", "password123");
        let q = start_link(&a);
        sign_out(&a);
        let landing = answer(&come_back_to(&b, &q), &q);
        assert_eq!(landing.location, "https://kb.test/settings/profile?sso_error=other_session");
        assert_eq!(linked(), 0);
        // Another live session of the same person can't finish it either.
        let c = sign_in(&h, "mo@acme.test", "password123");
        let q = start_link(&b);
        assert_eq!(answer(&come_back_to(&c, &q), &q).error(), "other_session");
        assert_eq!(linked(), 0);
        // Signed out after the provider answered but before the link is made: still refused.
        let q = start_link(&b);
        let r = come_back_to(&b, &q);
        assert!(!r.effects.is_empty(), "the callback itself was fine");
        sign_out(&b);
        assert_eq!(answer(&r, &q).error(), "other_session");
        assert_eq!(linked(), 0);
        // The same session, still signed in, links.
        let q = start_link(&c);
        let landing = answer(&come_back_to(&c, &q), &q);
        assert_eq!(landing.location, "https://kb.test/settings/profile?sso_linked=1");
        assert_eq!(linked(), 1);
        assert_eq!(links_logged(&h, &admin), vec![(mo_id, "self".to_string())]);
    }

    #[test]
    fn a_client_secret_the_server_cant_read_turns_sso_off() {
        let (mut h, admin) = workspace();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({ "require_sso": true }));
        let login = |h: &H| {
            h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "mo@acme.test", "password": "password123" })), &Auth::None).status
        };
        assert_eq!(login(&h), 403);
        assert!(h.ok("GET", "/api/v1/sso", None, &admin)["client_secret_unreadable"] == false);

        // The server's connector key changes: the secret sealed with the old one can't be read.
        h.cfg.connectors.key = Some("a-rotated-connector-key".into());
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!(
            (s["active"].as_bool(), s["enabled"].as_bool(), s["client_secret_set"].as_bool(), s["client_secret_unreadable"].as_bool()),
            (Some(false), Some(true), Some(true), Some(true)),
            "{s}"
        );
        // So single sign-on is off: no button, no sign-ins, and passwords work for everyone.
        assert!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"].is_null());
        let r = h.call("GET", "/sso/start", None, &Auth::None);
        assert!(r.effects.is_empty() && land(&r, None).error() == "not_configured");
        assert_eq!(login(&h), 200, "Require SSO doesn't lock people out while SSO can't work");

        // Saving it on without the secret says to enter it again; entering it turns it back on.
        let r = h.call("PATCH", "/api/v1/sso", Some(json!({ "auto_provision": false })), &admin);
        assert_eq!(r.status, 400);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("`client_secret` again"), "{}", r.body);
        let v = set_up(&h, &admin, json!({ "client_secret": "shh-client-secret" }), OKTA);
        assert_eq!((v["active"].as_bool(), v["client_secret_unreadable"].as_bool()), (Some(true), Some(false)));
        assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"]["required"], true);
        assert_eq!(login(&h), 403);
    }

    #[test]
    fn userinfo_can_vouch_for_the_id_tokens_email() {
        let (h, admin) = workspace();
        let (mo_id, _) = h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({}));
        // The ID token gives Mo's address but doesn't say whether it's verified.
        let id_token = || claims(OKTA, "sub-mo", "mo@acme.test", json!({}));
        let provider = |info: HttpReply| {
            move |call: &HttpCall, jwt: &str| {
                if call.url.ends_with("/userinfo") {
                    assert!(call.headers.contains(&("authorization".into(), "Bearer provider-access-token".into())));
                    info.clone()
                } else {
                    tokens(call, jwt)
                }
            }
        };
        let sign_in = |info: HttpReply, c: Value| {
            let s = start(&h, OKTA);
            come_back(&h, &s, c, &provider(info))
        };
        let refused = |info: HttpReply, c: Value| {
            let (landing, sent) = sign_in(info, c);
            assert!(landing.session().is_none());
            (landing.error(), sent.len())
        };

        // An answer about another account, or another address, vouches for nothing.
        let other_account = ok(json!({ "sub": "sub-eve", "email": "mo@acme.test", "email_verified": true }));
        assert_eq!(refused(other_account, id_token()), ("unverified_email".to_string(), 2));
        let other_address = ok(json!({ "sub": "sub-mo", "email": "eve@acme.test", "email_verified": true }));
        assert_eq!(refused(other_address, id_token()), ("unverified_email".to_string(), 2));
        // No answer at all (or one that isn't JSON): the ID token alone decides.
        assert_eq!(refused(HttpReply::default(), id_token()), ("unverified_email".to_string(), 2));
        assert_eq!(
            refused(HttpReply { status: 200, body: "eyJhbGciOiJSUzI1NiJ9.e30.c2ln".into() }, id_token()),
            ("unverified_email".to_string(), 2)
        );
        // An ID token that says the address isn't verified isn't overruled, so nobody asks.
        let unverified = claims(OKTA, "sub-mo", "mo@acme.test", json!({ "email_verified": false }));
        let verified_answer = || ok(json!({ "sub": "sub-mo", "email": "MO@acme.test", "email_verified": true }));
        assert_eq!(refused(verified_answer(), unverified), ("unverified_email".to_string(), 1));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sso_identities"), 0);

        // The same account vouching for the same address: Mo is matched and linked.
        let (landing, sent) = sign_in(verified_answer(), id_token());
        assert_eq!(sent.len(), 2);
        assert!(sent[1].url.ends_with("/userinfo"));
        assert_eq!(me(&h, &landing.session().unwrap_or_else(|| panic!("{}", landing.error())))["id"], mo_id.as_str());
        // Linked now, so later sign-ins don't need to ask.
        let (landing, sent) = sign_in(HttpReply::default(), id_token());
        assert!(landing.session().is_some());
        assert_eq!(sent.len(), 1);
    }

    #[test]
    fn saving_settings_keeps_its_webhooks_next_to_the_check() {
        let (h, admin) = workspace();
        h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.test/dumbslab", "events": ["sso.*"] })), &admin);
        let r = h.call(
            "PATCH",
            "/api/v1/sso",
            Some(json!({ "provider": "okta", "issuer": OKTA, "client_id": "app-id", "client_secret": "shh-client-secret" })),
            &admin,
        );
        assert_eq!(r.status, 200, "{}", r.body);
        // One job (the discovery check) and the `sso.updated` delivery, which hosts send after the job.
        let jobs = r.effects.iter().filter(|e| matches!(e, Effect::Connect(_))).count();
        let hooks: Vec<_> = r
            .effects
            .iter()
            .filter_map(|e| match e {
                Effect::Webhook(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!((jobs, hooks.len()), (1, 1), "{:?}", r.effects);
        assert!(hooks[0].headers.contains(&("x-dumbslab-event".into(), "sso.updated".into())));
        assert!(!hooks[0].body.contains("shh-client-secret"));
        // Connected apps' requests are unchanged: just their job.
        let r = h.call("POST", "/api/v1/connections", Some(json!({ "app": "github", "fields": { "token": "ghp_x" } })), &admin);
        assert_eq!(r.effects.len(), 1);
        assert!(matches!(r.effects[0], Effect::Connect(_)));
    }
}
