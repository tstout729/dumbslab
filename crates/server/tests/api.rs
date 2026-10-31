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

#[test]
fn directory_forwards_github_installations_to_the_workspaces_that_connected_them() {
    use chrono::Utc;
    use dumbslab_core::tenancy::{self, Limits};
    let h = H::new();
    let limits = Limits { per_ip_per_day: 500, per_day: 500, max_workspaces: 500, free: ROOMY };
    let now = Utc::now();
    let run = |f: &dyn Fn(&dyn dumbslab_core::Db) -> dumbslab_core::ApiResult<()>| {
        h.store
            .with_tx(|db| {
                let r = f(db);
                let ok = r.is_ok();
                (r, ok)
            })
            .unwrap()
    };
    let link = |id: i64, home: &'static str, linked: bool| run(&move |db| tenancy::link_installation(db, id, home, linked, now));
    let targets = |id: i64| h.store.with_tx(|db| (tenancy::installation_targets(db, id), true)).unwrap().unwrap();
    let pair = |home: &str, address: &str| (home.to_string(), address.to_string());
    run(&|db| tenancy::directory_migrate(db)).unwrap();
    for slug in ["acme", "beta", "gamma"] {
        run(&move |db| tenancy::reserve(db, slug, "Name", "ip", now, limits).map(|_| ())).unwrap();
        run(&move |db| tenancy::activate(db, slug, now)).unwrap();
    }
    run(&|db| tenancy::reserve(db, "pending", "Name", "ip", now, limits).map(|_| ())).unwrap();

    // One installation can serve several workspaces; linking twice changes nothing.
    link(42, "acme", true).unwrap();
    link(42, "acme", true).unwrap();
    link(42, "beta", true).unwrap();
    link(7, "gamma", true).unwrap();
    assert_eq!(targets(42), vec![pair("acme", "acme"), pair("beta", "beta")]);
    assert_eq!(targets(99), vec![], "nobody connected it");
    assert_eq!(link(42, "pending", true).unwrap_err().status, 404, "only set-up workspaces");
    assert_eq!(link(0, "acme", true).unwrap_err().status, 400);
    assert_eq!(link(5, "../x", true).unwrap_err().status, 400);

    // Deliveries go to the workspace's current address, and not to a disabled one.
    run(&|db| tenancy::move_address(db, "acme", "acme-wiki", now)).unwrap();
    assert_eq!(targets(42), vec![pair("acme", "acme-wiki"), pair("beta", "beta")]);
    run(&|db| tenancy::set_status(db, "beta", "disabled")).unwrap();
    assert_eq!(targets(42), vec![pair("acme", "acme-wiki")]);

    // Stopping, and deleting a workspace, remove its links.
    link(42, "acme", false).unwrap();
    assert_eq!(targets(42), vec![]);
    run(&|db| tenancy::remove(db, "gamma")).unwrap();
    assert_eq!(targets(7), vec![]);

    // At most so many workspaces per installation: each delivery wakes them all.
    for i in 0..tenancy::MAX_WORKSPACES_PER_INSTALLATION {
        let slug: &'static str = Box::leak(format!("ws-{i:03}").into_boxed_str());
        run(&move |db| tenancy::reserve(db, slug, "Name", "ip", now, limits).map(|_| ())).unwrap();
        run(&move |db| tenancy::activate(db, slug, now)).unwrap();
        link(8, slug, true).unwrap();
    }
    run(&|db| tenancy::reserve(db, "late", "Name", "ip", now, limits).map(|_| ())).unwrap();
    run(&|db| tenancy::activate(db, "late", now)).unwrap();
    let full = link(8, "late", true).unwrap_err();
    assert_eq!((full.status, full.code), (409, "installation_full"), "a code the workspace can tell the admin");
}

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
    // Run the scrub (0004) again. Only it: a later migration that adds a column can't run twice.
    let scrub = dumbslab_core::db::MIGRATIONS.iter().find(|m| m.contains("UPDATE activity SET data = '{}'")).unwrap();
    h.store.with_tx(|db| (db.execute_batch(scrub), true)).unwrap().unwrap();
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

#[test]
fn imports_skip_what_exists_and_stay_quiet() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, member) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, other) = h.user(&admin, "otto@acme.test", "Otto Other", "member");
    let (_, viewer) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");
    let docs = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Docs" })), &admin)["id"].as_str().unwrap().to_string();
    h.ok("POST", "/api/v1/follows", Some(json!({ "target_type": "topic", "target_id": docs })), &viewer);

    // Viewers can't import.
    let one = json!({ "documents": [{ "title": "x", "content": "y" }] });
    assert_eq!(h.call("POST", "/api/v1/import", Some(one), &viewer).status, 403);

    // An image uploaded before the import joins the post that uses it.
    let png = b"\x89PNG\r\n\x1a\nimported";
    let file = upload(&h, &member, "diagram.png", None, png, None).body;
    let batch = json!({ "skip_existing": true, "documents": [
        { "title": "Home", "content": format!("Welcome @vic\n\n{}", file["markdown"].as_str().unwrap()), "topic": "Docs" },
        { "title": "Runbook", "content": "Steps", "topic": "Docs/Ops" },
        { "title": "Loose page", "content": "No topic" },
    ] });
    let first = h.ok("POST", "/api/v1/import", Some(batch.clone()), &member);
    assert_eq!(first["created"].as_array().unwrap().len(), 3);
    assert_eq!(first["topics_created"], 1);
    let first_ids: Vec<&str> = first["results"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert!(first["results"].as_array().unwrap().iter().all(|r| r["skipped"] == false));
    assert_eq!(first["results"][1]["title"], "Runbook");
    let home = first_ids[0];
    let fid = file["id"].as_str().unwrap();
    assert_eq!(h.ok("GET", &format!("/api/v1/files/{fid}"), None, &member)["post_id"], home);

    // Imported pages don't notify topic followers or the people their text mentions.
    let n = h.ok("GET", "/api/v1/notifications", None, &viewer);
    assert!(n["items"].as_array().unwrap().iter().all(|x| !first_ids.contains(&x["post"]["id"].as_str().unwrap_or_default())), "{n}");
    // The activity feed still records each new post.
    let feed = h.ok("GET", &format!("/api/v1/activity?post_id={home}"), None, &viewer);
    assert_eq!(feed["items"][0]["event"], "post.created");

    // Running the same import again creates nothing and reports the posts it matched, in order.
    let again = h.ok("POST", "/api/v1/import", Some(batch.clone()), &member);
    assert!(again["created"].as_array().unwrap().is_empty(), "{again}");
    assert_eq!(again["skipped"].as_array().unwrap().len(), 3);
    assert_eq!(again["topics_created"], 0);
    let again_ids: Vec<&str> = again["results"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(again_ids, first_ids);
    assert!(again["results"].as_array().unwrap().iter().all(|r| r["skipped"] == true));

    // The match is exact title in the same topic: other topics, other titles and trashed posts don't count.
    h.ok("DELETE", &format!("/api/v1/posts/{}", first_ids[2]), None, &member);
    let mixed = h.ok(
        "POST",
        "/api/v1/import",
        Some(json!({ "skip_existing": true, "documents": [
            { "title": "Runbook", "content": "Elsewhere", "topic": "Docs" },
            { "title": "runbook", "content": "Case differs", "topic": "Docs/Ops" },
            { "title": "Loose page", "content": "Back from the trash" },
            { "title": "New page", "content": "a", "topic": "Docs" },
            { "title": "New page", "content": "b", "topic": "Docs" },
        ] })),
        &member,
    );
    let skipped: Vec<bool> = mixed["results"].as_array().unwrap().iter().map(|r| r["skipped"].as_bool().unwrap()).collect();
    assert_eq!(skipped, [false, false, false, false, true], "{mixed}");
    assert_eq!(mixed["results"][4]["id"], mixed["results"][3]["id"]);

    // Someone else's draft stays invisible, so it is neither matched nor revealed.
    let draft =
        json!({ "skip_existing": true, "documents": [{ "title": "Plans", "content": "draft", "topic": "Docs", "status": "draft" }] });
    let mine = h.ok("POST", "/api/v1/import", Some(draft.clone()), &member);
    let theirs = h.ok("POST", "/api/v1/import", Some(draft), &other);
    assert_eq!(theirs["results"][0]["skipped"], false);
    assert_ne!(theirs["results"][0]["id"], mine["results"][0]["id"]);

    // Without `skip_existing`, an import still creates every document, as before.
    let dup =
        h.ok("POST", "/api/v1/import", Some(json!({ "documents": [{ "title": "Home", "content": "again", "topic": "Docs" }] })), &member);
    assert_ne!(dup["created"][0]["id"], home);
}

#[test]
fn imports_into_a_private_topic_stay_private() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (mia_id, mia) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, otto) = h.user(&admin, "otto@acme.test", "Otto Outsider", "member");
    let (_, vic) = h.user(&admin, "vic@acme.test", "Vic Viewer", "viewer");
    let leadership =
        h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Leadership", "visibility": "private", "members": [mia_id] })), &admin);
    let lid = leadership["id"].as_str().unwrap().to_string();

    // Mia imports under the private topic; the topics the import creates there are private too.
    let r = h.ok(
        "POST",
        "/api/v1/import",
        Some(json!({ "skip_existing": true, "documents": [
            { "title": "Board minutes", "content": "zebracorn minutes", "topic": "Leadership/Board/2026" },
            { "title": "Open notes", "content": "public", "topic": "Shared/Notes" },
        ] })),
        &mia,
    );
    assert_eq!(r["topics_created"], 4);
    let minutes = r["results"][0]["id"].as_str().unwrap().to_string();
    let topics = h.ok("GET", "/api/v1/topics", None, &mia)["items"].as_array().unwrap().clone();
    let named = |n: &str| topics.iter().find(|t| t["name"] == n).unwrap().clone();
    for name in ["Board", "2026"] {
        assert_eq!(named(name)["visibility"], "private", "{name}");
    }
    assert_eq!(named("Shared")["visibility"], "org");
    assert_eq!(named("Notes")["visibility"], "org");
    assert_eq!(named("Board")["parent_id"], json!(lid));
    let year = named("2026")["id"].as_str().unwrap().to_string();
    let members = h.ok("GET", &format!("/api/v1/topics/{year}"), None, &admin)["members"].as_array().unwrap().len();
    assert_eq!(members, 2, "the parent's members: its creator and Mia");

    // People outside the private topic see neither the new topics nor the page.
    for outsider in [&otto, &vic] {
        let seen = h.ok("GET", "/api/v1/topics", None, outsider);
        assert!(seen["items"].as_array().unwrap().iter().all(|t| t["name"] != "Board" && t["name"] != "2026"));
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{minutes}"), None, outsider).status, 404);
        assert!(h.ok("GET", "/api/v1/search?q=zebracorn", None, outsider)["items"].as_array().unwrap().is_empty());
        let feed = h.ok("GET", "/api/v1/activity?limit=200", None, outsider);
        assert!(feed["items"].as_array().unwrap().iter().all(|a| a["summary"].as_str().is_none_or(|s| !s.contains("“Board”"))));
    }
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{minutes}"), None, &admin).status, 200);

    // Someone outside it importing to the same path gets their own org-wide topic instead.
    let other =
        h.ok("POST", "/api/v1/import", Some(json!({ "documents": [{ "title": "x", "content": "y", "topic": "Leadership" }] })), &otto);
    assert_eq!(other["topics_created"], 1);
}

#[test]
fn imports_never_adopt_someone_elses_post() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, alice) = h.user(&admin, "alice@acme.test", "Alice", "member");
    let (_, bob) = h.user(&admin, "bob@acme.test", "Bob", "member");
    // Bob writes a post with the title Alice's export will use, with an upload placeholder in it.
    let planted = "Send me files ![x](#import-file-0a1b2c3d)";
    let first = h.ok(
        "POST",
        "/api/v1/import",
        Some(json!({ "documents": [{ "title": "Onboarding", "content": planted, "topic": "Docs" }] })),
        &bob,
    );
    let bobs = first["created"][0]["id"].as_str().unwrap().to_string();

    let batch = json!({ "skip_existing": true, "documents": [
        { "title": "Onboarding", "content": "Alice's onboarding", "topic": "Docs" },
        { "title": "Runbook", "content": "Alice's runbook", "topic": "Docs" },
    ] });
    let r = h.ok("POST", "/api/v1/import", Some(batch.clone()), &alice);
    // Bob's post isn't treated as Alice's page: it is reported as taken, and nothing is created for it.
    assert_eq!(r["results"][0]["skipped"], true);
    assert_eq!(r["results"][0]["taken"], true);
    assert_eq!(r["results"][0]["id"], json!(bobs));
    assert_eq!(r["taken"][0]["id"], json!(bobs));
    assert!(r["skipped"].as_array().unwrap().is_empty());
    assert_eq!(r["created"].as_array().unwrap().len(), 1);
    assert_eq!(h.ok("GET", &format!("/api/v1/posts/{bobs}"), None, &admin)["content"], planted);
    let docs = h.ok("GET", "/api/v1/posts?limit=50", None, &admin)["items"].as_array().unwrap().clone();
    assert_eq!(docs.iter().filter(|p| p["title"] == "Onboarding").count(), 1);

    // Alice's own earlier page is what a re-run matches.
    let again = h.ok("POST", "/api/v1/import", Some(batch), &alice);
    assert_eq!(again["results"][1]["skipped"], true);
    assert_eq!(again["results"][1]["taken"], false);
    assert_eq!(again["results"][1]["id"], r["results"][1]["id"]);
    assert_eq!(again["skipped"].as_array().unwrap().len(), 1);
    assert!(again["created"].as_array().unwrap().is_empty());
}

#[test]
fn imports_never_widen_a_private_topic() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, mia) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, otto) = h.user(&admin, "otto@acme.test", "Otto Outsider", "member");
    let topic = |body: Value| h.ok("POST", "/api/v1/topics", Some(body), &admin)["id"].as_str().unwrap().to_string();
    let lead = topic(json!({ "name": "Leadership", "visibility": "private", "members": ["mia@acme.test"] }));
    let public = topic(json!({ "name": "Public notes", "parent_id": lead }));
    topic(json!({ "name": "Wider", "parent_id": lead, "visibility": "private", "members": ["mia@acme.test", "otto@acme.test"] }));
    topic(json!({ "name": "Board", "parent_id": lead, "visibility": "private", "members": ["mia@acme.test"] }));
    let import = |body: Value, who: &Auth| h.call("POST", "/api/v1/import", Some(body), who);
    let one = |path: &str| json!({ "documents": [{ "title": "Minutes", "content": "zebracorn", "topic": path }] });
    let before = h.ok("GET", "/api/v1/topics", None, &admin)["items"].as_array().unwrap().len();

    // A topic inside the private one that more people can see is refused, for pages in it and under it.
    for path in ["Leadership/Public notes", "Leadership/Public notes/Deeper", "Leadership/Wider"] {
        let r = import(one(path), &mia);
        assert_eq!(r.status, 409, "{path}: {}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("inside the private topic “Leadership”"), "{}", r.body);
    }
    assert_eq!(h.ok("GET", "/api/v1/topics", None, &admin)["items"].as_array().unwrap().len(), before, "nothing was created");
    assert_eq!(h.ok("GET", &format!("/api/v1/topics/{public}"), None, &admin)["visibility"], "org", "and nothing changed");
    assert!(h.ok("GET", "/api/v1/search?q=zebracorn", None, &admin)["items"].as_array().unwrap().is_empty());

    // A private topic with the same members or fewer is fine; topics created in it are private.
    let ok = h.ok("POST", "/api/v1/import", Some(one("Leadership/Board/2026")), &mia);
    assert_eq!(ok["topics_created"], 1);
    let year = h.ok("GET", "/api/v1/topics", None, &mia)["items"].as_array().unwrap().iter().find(|t| t["name"] == "2026").unwrap().clone();
    assert_eq!(year["visibility"], "private");

    // `topic_id` names the destination itself: paths go inside it, under the same rules.
    let inside = h.ok(
        "POST",
        "/api/v1/import",
        Some(json!({ "topic_id": lead, "documents": [{ "title": "Charter", "content": "x" }, { "title": "Notes", "content": "y", "topic": "Board" }] })),
        &mia,
    );
    let charter = inside["results"][0]["id"].as_str().unwrap();
    let topics = h.ok("GET", &format!("/api/v1/posts/{charter}"), None, &mia)["topics"].clone();
    assert_eq!(topics[0]["id"], json!(lead));
    assert_eq!(
        import(json!({ "topic_id": lead, "documents": [{ "title": "x", "content": "y", "topic": "Public notes" }] }), &mia).status,
        409
    );
    assert_eq!(h.call("GET", &format!("/api/v1/posts/{charter}"), None, &otto).status, 404);
    // A topic the caller can't see can't be a destination.
    assert_eq!(import(json!({ "topic_id": lead, "documents": [{ "title": "x", "content": "y" }] }), &otto).status, 404);
}

#[test]
fn admins_import_into_private_topics_they_have_not_joined() {
    let h = H::new();
    let (_, admin) = h.setup();
    let (_, mia) = h.user(&admin, "mia@acme.test", "Mia Member", "member");
    let (_, otto) = h.user(&admin, "otto@acme.test", "Otto Outsider", "member");
    // Mia's private topic; the admin isn't a member but, as an admin, can see it.
    let exec =
        h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Exec", "visibility": "private" })), &mia)["id"].as_str().unwrap().to_string();
    let members = h.ok("GET", &format!("/api/v1/topics/{exec}"), None, &admin)["members"].as_array().unwrap().len();
    assert_eq!(members, 1);

    // Two pages share a child the import creates; the importer joining it widens nothing.
    let batch = json!({ "skip_existing": true, "topic_id": exec, "documents": [
        { "title": "Q1 plan", "content": "zebracorn one", "topic": "Plans" },
        { "title": "Q2 plan", "content": "zebracorn two", "topic": "Plans" },
    ] });
    let r = h.ok("POST", "/api/v1/import", Some(batch.clone()), &admin);
    assert_eq!(r["created"].as_array().unwrap().len(), 2, "{r}");
    assert_eq!(r["topics_created"], 1);
    let plans =
        h.ok("GET", "/api/v1/topics", None, &mia)["items"].as_array().unwrap().iter().find(|t| t["name"] == "Plans").unwrap().clone();
    assert_eq!(plans["visibility"], "private");
    assert_eq!(h.ok("GET", "/api/v1/search?q=zebracorn", None, &mia)["items"].as_array().unwrap().len(), 2);
    assert!(h.ok("GET", "/api/v1/search?q=zebracorn", None, &otto)["items"].as_array().unwrap().is_empty());

    // Running it again skips both, and creates nothing.
    let again = h.ok("POST", "/api/v1/import", Some(batch), &admin);
    assert_eq!(again["skipped"].as_array().unwrap().len(), 2, "{again}");
    assert!(again["created"].as_array().unwrap().is_empty());
    assert_eq!(again["topics_created"], 0);

    // A child with a real extra reader is still refused, for admins too.
    h.ok(
        "POST",
        "/api/v1/topics",
        Some(json!({ "name": "Shared", "parent_id": exec, "visibility": "private", "members": ["otto@acme.test"] })),
        &admin,
    );
    let wider = h.call(
        "POST",
        "/api/v1/import",
        Some(json!({ "topic_id": exec, "documents": [{ "title": "x", "content": "y", "topic": "Shared" }] })),
        &admin,
    );
    assert_eq!(wider.status, 409, "{}", wider.body);
}

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

#[test]
fn telemetry_settings_reach_the_web_app_only_when_configured() {
    use dumbslab_core::telemetry::Telemetry;
    let mut h = H::new();
    let (cookie, _) = h.setup();
    // Self-hosted servers report nowhere unless their operator says so.
    assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &cookie)["telemetry"], Value::Null);
    assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["telemetry"], Value::Null);

    let dsn = "https://abc123@o1.ingest.us.sentry.io/42";
    h.cfg.telemetry = Telemetry::new(Some("https://t.example.com"), Some("phc_public"), Some(dsn)).0;
    h.cfg.workspace = Some("acme".into());
    let telemetry = h.ok("GET", "/api/v1/auth/state", None, &cookie)["telemetry"].clone();
    assert_eq!(telemetry["quill"], json!({ "host": "https://t.example.com", "token": "phc_public" }));
    assert_eq!(telemetry["sentry"], json!({ "dsn": dsn }));
    assert_eq!(telemetry["workspace"], "acme");

    // Only error reports: recordings stay off.
    h.cfg.telemetry = Telemetry::new(None, None, Some(dsn)).0;
    let telemetry = h.ok("GET", "/api/v1/auth/state", None, &cookie)["telemetry"].clone();
    assert_eq!((telemetry["quill"].clone(), telemetry["sentry"]["dsn"].clone()), (Value::Null, json!(dsn)));

    // A DSN with a secret never reaches a browser: error reports stay off.
    let (secret, problems) = Telemetry::new(None, None, Some("https://public:secret@o1.ingest.us.sentry.io/42"));
    assert_eq!(problems.len(), 1);
    h.cfg.telemetry = secret;
    let state = h.ok("GET", "/api/v1/auth/state", None, &Auth::None);
    assert_eq!(state["telemetry"], Value::Null);
    assert!(!state.to_string().contains("secret"));
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

    /// Zendesk at `acme.zendesk.com`, answering a global OAuth client's sign-in and the API.
    fn zendesk(call: &HttpCall) -> HttpReply {
        let url = call.url.as_str();
        if url == "https://acme.zendesk.com/oauth/tokens" {
            let body: Value = serde_json::from_str(call.body.as_deref().unwrap_or("{}")).unwrap();
            let n = if body["grant_type"] == "refresh_token" { 2 } else { 1 };
            HttpReply {
                status: 201,
                body: json!({ "access_token": format!("zd-at-{n}"), "refresh_token": format!("zd-rt-{n}"), "token_type": "bearer",
                    "scope": "read", "expires_in": 28800, "refresh_token_expires_in": 7776000 })
                .to_string(),
            }
        } else if url == "https://acme.zendesk.com/api/v2/users/me.json" {
            ok(json!({ "user": { "id": 7, "name": "Ada", "email": "ada@acme.com", "role": "agent" } }))
        } else if url.starts_with("https://acme.zendesk.com/api/v2/search.json") {
            ok(json!({ "results": [{ "result_type": "ticket", "id": 12, "subject": "Printer jams", "status": "open" }] }))
        } else if url.starts_with("https://acme.zendesk.com/api/v2/help_center/") {
            ok(json!({ "results": [] }))
        } else {
            HttpReply { status: 404, body: "{}".into() }
        }
    }

    #[test]
    fn signing_in_with_zendesk_stays_on_the_persons_subdomain() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let user_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        let app = |h: &H| {
            let list = h.ok("GET", "/api/v1/connections", None, &admin);
            list["apps"].as_array().unwrap().iter().find(|a| a["id"] == "zendesk").unwrap().clone()
        };
        let start = |h: &H, body: Value| h.call("POST", "/api/v1/connections", Some(body), &admin);

        // Without a global OAuth client, Zendesk takes only tokens.
        let z = app(&h);
        assert_eq!((z["sign_in"].as_bool(), z["sign_in_field"].is_null()), (Some(false), true));
        assert_eq!(start(&h, json!({ "app": "zendesk", "site": "acme" })).status, 400);

        h.cfg.connectors.apps.insert("zendesk".into(), OAuthApp { client_id: "zdg-dumbslab".into(), client_secret: "zsecret".into() });
        h.cfg.connectors.apps.insert("github".into(), OAuthApp { client_id: "cid".into(), client_secret: "csecret".into() });
        let z = app(&h);
        assert_eq!((z["sign_in"].as_bool(), z["sign_in_field"]["key"].as_str()), (Some(true), Some("subdomain")));
        assert_eq!(z["token_fields"][0]["key"], "subdomain", "tokens still work");

        // The subdomain is required and checked strictly; nothing is recorded for a refused one.
        for bad in [
            json!(null),
            json!(" "),
            json!("evil.test#"),
            json!("a.b"),
            json!("acme.zendesk.com.evil.test"),
            json!("acme.zendesk.com:8443"),
            json!("https://acme.zendesk.com@evil.test/"),
            json!("ácme"),
        ] {
            let r = start(&h, json!({ "app": "zendesk", "site": bad }));
            assert_eq!(r.status, 400, "{bad}: {}", r.body);
        }
        assert_eq!(count(&h, "SELECT COUNT(*) FROM connect_requests"), 0);
        // Apps with one sign-in for everyone refuse a site, and tokens don't take one.
        assert_eq!(start(&h, json!({ "app": "github", "site": "acme" })).status, 400);
        let token = json!({ "app": "zendesk", "site": "acme", "fields": { "subdomain": "acme", "email": "ada@acme.com", "token": "t" } });
        assert_eq!(start(&h, token).status, 400);

        // Signing in starts on the person's own subdomain.
        let url = start(&h, json!({ "app": "zendesk", "site": " ACME.zendesk.com " })).body["authorize_url"].as_str().unwrap().to_string();
        assert!(url.starts_with("https://acme.zendesk.com/oauth/authorizations/new?"), "{url}");
        let q = query_of(&url);
        assert_eq!(
            (q["client_id"].as_str(), q["redirect_uri"].as_str(), q["scope"].as_str(), q["response_type"].as_str()),
            ("zdg-dumbslab", "https://kb.test/connect/callback", "read", "code")
        );
        assert_eq!(q["code_challenge_method"], "S256");
        // The subdomain stays on the server, out of the state the browser carries.
        assert!(!q["state"].contains("acme"));

        // Coming back: anything the browser adds can't move the exchange to another Zendesk.
        let r = h.call(
            "GET",
            &format!("/connect/callback?code=zd-code&subdomain=evil&site=evil.test&state={}", urlencoding::encode(&q["state"])),
            None,
            &admin,
        );
        let (finish, sent) = drive(&h, job_of(&r), &zendesk);
        assert!(matches!(&finish, Finish::Redirect(u) if u == "https://kb.test/settings/connections?connected=zendesk"), "{finish:?}");
        assert!(sent.iter().all(|c| c.url.starts_with("https://acme.zendesk.com/")), "{sent:?}");
        let exchange = &sent[0];
        assert_eq!((exchange.method, exchange.url.as_str()), ("POST", "https://acme.zendesk.com/oauth/tokens"));
        let body: Value = serde_json::from_str(exchange.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            (&body["grant_type"], &body["code"], &body["client_id"], &body["client_secret"], &body["scope"]),
            (&json!("authorization_code"), &json!("zd-code"), &json!("zdg-dumbslab"), &json!("zsecret"), &json!("read"))
        );
        assert_eq!(body["redirect_uri"], "https://kb.test/connect/callback");
        let verifier = body["code_verifier"].as_str().unwrap();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, q["code_challenge"], "PKCE with the verifier kept on the server");
        assert!(sent[1].headers.contains(&("authorization".into(), "Bearer zd-at-1".into())));
        assert_eq!(app(&h)["connected"]["account"], "ada@acme.com (acme.zendesk.com)");
        // The token is sealed with its subdomain.
        let secret =
            || h.store.with_tx(|db| (db.one("SELECT secret FROM connections", &[]).unwrap().unwrap().str("secret"), true)).unwrap();
        assert!(!secret().contains("zd-at-1"));
        let cred = connect::open("connector-key", &user_id, "zendesk", &secret()).unwrap();
        assert_eq!((cred.token.as_str(), cred.refresh_token.as_deref(), cred.field("subdomain")), ("zd-at-1", Some("zd-rt-1"), "acme"));

        // Searching uses the token on that subdomain; once it nearly expires, it's refreshed there first.
        let search = || {
            let r = h.call("GET", "/api/v1/search/connected?q=printer", None, &admin);
            let (finish, sent) = drive(&h, job_of(&r), &zendesk);
            (filled(&r, finish), sent)
        };
        let (v, sent) = search();
        assert_eq!(v["items"][0]["url"], "https://acme.zendesk.com/agent/tickets/12", "{v}");
        assert!(sent.iter().all(|c| c.headers.contains(&("authorization".into(), "Bearer zd-at-1".into()))));
        let soon = dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::minutes(1));
        h.store.with_tx(|db| (db.execute("UPDATE connections SET expires_at = ?", &dumbslab_core::params![soon]), true)).unwrap().unwrap();
        let (v, sent) = search();
        assert_eq!(v["apps"][0]["ok"], true, "{v}");
        assert_eq!(sent[0].url, "https://acme.zendesk.com/oauth/tokens");
        let refresh: Value = serde_json::from_str(sent[0].body.as_deref().unwrap()).unwrap();
        assert_eq!((&refresh["grant_type"], &refresh["refresh_token"]), (&json!("refresh_token"), &json!("zd-rt-1")));
        assert!(sent[1..].iter().all(|c| c.headers.contains(&("authorization".into(), "Bearer zd-at-2".into()))));
        assert_eq!(connect::open("connector-key", &user_id, "zendesk", &secret()).unwrap().refresh_token.as_deref(), Some("zd-rt-2"));

        // Even if the saved settings named another Zendesk, the token never goes there.
        let beta = json!({ "host": "beta.zendesk.com", "user_id": 7 }).to_string();
        h.store.with_tx(|db| (db.execute("UPDATE connections SET settings = ?", &dumbslab_core::params![beta]), true)).unwrap().unwrap();
        let (_, sent) = search();
        assert!(sent.is_empty(), "{sent:?}");
        let r = h.call(
            "GET",
            &format!("/api/v1/connections/preview?url={}", urlencoding::encode("https://beta.zendesk.com/agent/tickets/9")),
            None,
            &admin,
        );
        let (_, sent) = drive(&h, job_of(&r), &zendesk);
        assert!(sent.is_empty(), "{sent:?}");
    }

    #[test]
    fn a_zendesk_refresh_revokes_the_old_token_without_stranding_other_requests() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.cfg.connectors.apps.insert("zendesk".into(), OAuthApp { client_id: "zdg-dumbslab".into(), client_secret: "zsecret".into() });
        let user_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        let now = chrono::Utc::now;
        // What's stored: a signed-in Zendesk connection at acme.zendesk.com.
        let set = |token: &str, refresh: &str, expires: chrono::DateTime<chrono::Utc>| {
            let cred = connect::Credential {
                token: token.into(),
                refresh_token: Some(refresh.into()),
                fields: [("subdomain".to_string(), "acme".to_string())].into(),
            };
            let sealed = connect::seal("connector-key", &user_id, "zendesk", &cred).unwrap();
            let settings = json!({ "host": "acme.zendesk.com", "user_id": 7 }).to_string();
            let (expires, at) = (dumbslab_core::util::ts(expires), dumbslab_core::util::ts(now()));
            h.store
                .with_tx(|db| {
                    db.execute("DELETE FROM connections", &[]).unwrap();
                    (db.execute(
                        "INSERT INTO connections (user_id, provider, account, settings, secret, expires_at, created_at, updated_at) VALUES (?, 'zendesk', 'ada@acme.com (acme.zendesk.com)', ?, ?, ?, ?, ?)",
                        &dumbslab_core::params![user_id.clone(), settings, sealed, expires, at.clone(), at],
                    ), true)
                })
                .unwrap()
                .unwrap();
        };
        // Zendesk, which revokes the access token it replaces the moment it refreshes, and refuses
        // any other with 401 invalid_token.
        let live = std::cell::RefCell::new(("zd-at-1".to_string(), "zd-rt-1".to_string()));
        let zendesk = |call: &HttpCall| -> HttpReply {
            let url = call.url.as_str();
            if url == "https://acme.zendesk.com/oauth/tokens" {
                let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
                if body["refresh_token"] != live.borrow().1.as_str() {
                    return HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() };
                }
                let n: u32 = live.borrow().1.trim_start_matches("zd-rt-").parse().unwrap();
                *live.borrow_mut() = (format!("zd-at-{}", n + 1), format!("zd-rt-{}", n + 1));
                let (at, rt) = live.borrow().clone();
                return HttpReply {
                    status: 201,
                    body: json!({ "access_token": at, "refresh_token": rt, "expires_in": 28800 }).to_string(),
                };
            }
            let bearer = call.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap_or_default();
            if bearer != format!("Bearer {}", live.borrow().0) {
                return HttpReply { status: 401, body: json!({ "error": "invalid_token" }).to_string() };
            }
            if url.contains("/api/v2/search.json") {
                ok(json!({ "results": [{ "result_type": "ticket", "id": 12, "subject": "Printer jams", "status": "open" }] }))
            } else if url.contains("/api/v2/tickets/9.json") {
                ok(json!({ "ticket": { "id": 9, "subject": "Refund", "status": "open" } }))
            } else {
                ok(json!({ "results": [] }))
            }
        };
        let revoke_to = |token: &str| live.borrow_mut().0 = token.into();
        let search = || job_of(&h.call("GET", "/api/v1/search/connected?q=printer", None, &admin));
        let preview = || {
            let link = urlencoding::encode("https://acme.zendesk.com/agent/tickets/9").into_owned();
            job_of(&h.call("GET", &format!("/api/v1/connections/preview?url={link}"), None, &admin))
        };
        let bearers = |calls: &[HttpCall]| -> Vec<String> {
            calls.iter().filter_map(|c| c.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone())).collect()
        };
        let answer = |calls: &[HttpCall]| -> Vec<HttpReply> { calls.iter().map(zendesk).collect() };
        let app_error = |v: &Value| v["apps"][0]["error"].as_str().unwrap_or_default().to_string();

        // 1. One request refreshes; the others, which Google Drive would let use the current token
        // meanwhile, wait instead: the refresh revokes it.
        set("zd-at-1", "zd-rt-1", now() + chrono::Duration::minutes(2));
        let (mut first, mut second, mut third) = (search(), search(), preview());
        let refreshing = fetches(step(&h, &mut first, vec![]));
        assert_eq!(refreshing[0].url, "https://acme.zendesk.com/oauth/tokens");
        let v = result(step(&h, &mut second, vec![]));
        assert!(app_error(&v).contains("Try again in a moment"), "{v}");
        assert!(result(step(&h, &mut third, vec![]))["error"].as_str().unwrap().contains("Try again in a moment"));
        // The refresh revokes zd-at-1; the first searches with the new token.
        let searching = fetches(step(&h, &mut first, answer(&refreshing)));
        assert!(bearers(&searching).iter().all(|b| b == "Bearer zd-at-2"), "{searching:?}");
        let v = result(step(&h, &mut first, answer(&searching)));
        assert_eq!((v["apps"][0]["ok"].as_bool(), v["items"][0]["title"].as_str()), (Some(true), Some("Printer jams")), "{v}");

        // 2. A search already sent with the old token when another request refreshed: refused, it
        // tries once more with the token saved meanwhile, rather than asking to reconnect.
        let mut late = search();
        let sent = fetches(step(&h, &mut late, vec![]));
        assert!(bearers(&sent).iter().all(|b| b == "Bearer zd-at-2"));
        set("zd-at-3", "zd-rt-3", now() + chrono::Duration::hours(8));
        revoke_to("zd-at-3");
        let again = fetches(step(&h, &mut late, answer(&sent)));
        assert!(!again.is_empty() && bearers(&again).iter().all(|b| b == "Bearer zd-at-3"), "{again:?}");
        let v = result(step(&h, &mut late, answer(&again)));
        assert_eq!(v["apps"][0]["ok"], true, "{v}");
        // The same for a preview.
        let mut late = preview();
        let sent = fetches(step(&h, &mut late, vec![]));
        set("zd-at-4", "zd-rt-4", now() + chrono::Duration::hours(8));
        revoke_to("zd-at-4");
        let again = fetches(step(&h, &mut late, answer(&sent)));
        assert_eq!(bearers(&again), ["Bearer zd-at-4"]);
        assert_eq!(result(step(&h, &mut late, answer(&again)))["preview"]["title"], "Refund");

        // 3. Refused while another request is still refreshing (its new token isn't saved yet):
        // try again in a moment, not reconnect.
        let mut caught = search();
        let sent = fetches(step(&h, &mut caught, vec![]));
        let lease = format!("{} other", dumbslab_core::util::ts(now() + chrono::Duration::seconds(30)));
        h.store
            .with_tx(|db| (db.execute("UPDATE connections SET refreshing_until = ?", &dumbslab_core::params![lease]), true))
            .unwrap()
            .unwrap();
        revoke_to("zd-at-5");
        let v = result(step(&h, &mut caught, answer(&sent)));
        assert!(app_error(&v).contains("Try again in a moment"), "{v}");

        // 4. A refusal with nothing newer saved and nobody refreshing still asks to reconnect.
        h.store.with_tx(|db| (db.execute("UPDATE connections SET refreshing_until = NULL", &[]), true)).unwrap().unwrap();
        let mut refused = search();
        let sent = fetches(step(&h, &mut refused, vec![]));
        let v = result(step(&h, &mut refused, answer(&sent)));
        assert!(app_error(&v).contains("Reconnect Zendesk"), "{v}");
    }

    #[test]
    fn one_atlassian_app_keeps_both_jira_and_confluence_granted() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let scope = |h: &H, app: &str| {
            let url =
                h.ok("POST", "/api/v1/connections", Some(json!({ "app": app })), &admin)["authorize_url"].as_str().unwrap().to_string();
            assert!(url.starts_with("https://auth.atlassian.com/authorize?"), "{url}");
            query_of(&url)["scope"].clone()
        };
        // The host's settings name one Atlassian app for both (ATLASSIAN_CLIENT_ID and _SECRET).
        let vars: std::collections::HashMap<&str, &str> =
            [("ATLASSIAN_CLIENT_ID", "atl"), ("ATLASSIAN_CLIENT_SECRET", "atl-secret")].into();
        h.cfg.connectors.apps = connect::oauth_apps(|name| vars.get(name).map(|v| v.to_string()));
        // Atlassian keeps one grant per person and app, replaced by each consent: each sign-in asks
        // for both products' scopes, so connecting one never takes away the other's.
        assert_eq!(scope(&h, "jira"), "read:jira-work offline_access search:confluence");
        assert_eq!(scope(&h, "confluence"), "search:confluence offline_access read:jira-work");
        // Separate apps ask only for their own.
        h.cfg.connectors.apps.insert("confluence".into(), OAuthApp { client_id: "conf".into(), client_secret: "conf-secret".into() });
        assert_eq!(scope(&h, "jira"), "read:jira-work offline_access");
        assert_eq!(scope(&h, "confluence"), "search:confluence offline_access");
    }

    /// Atlassian, answering a sign-in and connections with personal data DumbSlab mustn't keep.
    fn atlassian(call: &HttpCall) -> HttpReply {
        let url = call.url.as_str();
        if url == "https://auth.atlassian.com/oauth/token" {
            ok(json!({ "access_token": "atl-at", "refresh_token": "atl-rt", "expires_in": 3600, "scope": "read:jira-work offline_access" }))
        } else if url.ends_with("/oauth/token/accessible-resources") {
            ok(json!([{ "id": "1324a887-45db-1bf4-1e99-ef0ff456d421", "url": "https://acme.atlassian.net", "name": "Acme",
                "scopes": ["read:jira-work"], "avatarUrl": "https://x.test/a.png" }]))
        } else if url.ends_with("/rest/api/3/myself") {
            ok(json!({ "accountId": "5b10ac8d82e05b22cc7d4ef5", "emailAddress": "ada@acme.com", "displayName": "Ada Lovelace" }))
        } else if url.starts_with("https://api.trello.com/1/members/me") {
            ok(json!({ "id": "5abbe4b7ddc1b351ef961414", "username": "ada", "fullName": "Ada Lovelace" }))
        } else {
            HttpReply { status: 404, body: "{}".into() }
        }
    }

    #[test]
    fn upgrading_drops_personal_data_from_atlassian_and_trello_connections() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let (lin, _) = h.user(&admin, "lin@acme.test", "Lin", "member");
        let (bo, _) = h.user(&admin, "bo@acme.test", "Bo", "member");
        let me = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        // Rows as earlier versions saved them, each with its sealed credential.
        let rows: Vec<(String, &str, &str, Value)> = vec![
            (me.clone(), "jira", "Ada Lovelace on acme.atlassian.net", json!({ "site": "acme.atlassian.net", "cloud_id": "1324a887" })),
            (me.clone(), "confluence", "ada@acme.com on wiki.atlassian.net", json!({ "site": "wiki.atlassian.net" })),
            (me.clone(), "trello", "@ada", json!({ "id": "5abbe4b7ddc1b351ef961414", "username": "ada" })),
            (me.clone(), "github", "@ada", json!({ "login": "ada", "search_in": "user:ada" })),
            (lin.clone(), "jira", "ada@acme.com on acme.atlassian.net", json!({})),
            (bo.clone(), "jira", "bo@acme.com on acme.atlassian.net", json!("not an object")),
        ];
        let mut secrets = vec![];
        h.store
            .with_tx(|db| {
                for (user, app, label, settings) in &rows {
                    let cred = connect::Credential { token: format!("{app}-token"), ..Default::default() };
                    let sealed = connect::seal("connector-key", user, app, &cred).unwrap();
                    secrets.push(sealed.clone());
                    db.execute(
                        "INSERT INTO connections (user_id, provider, account, settings, secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, '2026-10-30T00:00:00.000Z', '2026-10-30T00:00:00.000Z')",
                        &dumbslab_core::params![user.clone(), *app, *label, settings.to_string(), sealed],
                    )
                    .unwrap();
                }
                // A row whose settings aren't JSON at all doesn't stop the upgrade.
                db.execute("UPDATE connections SET settings = 'oops' WHERE user_id = ? AND provider = 'jira'", &dumbslab_core::params![bo.clone()]).unwrap();
                ((), true)
            })
            .unwrap();

        // Run the migration again, as an upgrade from before it would.
        let sql = dumbslab_core::db::MIGRATIONS.iter().find(|m| m.contains("keep no personal data from Atlassian")).unwrap();
        h.store.with_tx(|db| (db.execute_batch(sql), true)).unwrap().unwrap();

        let after: Vec<(String, String, String)> = h
            .store
            .with_tx(|db| {
                let found = rows
                    .iter()
                    .map(|(user, app, _, _)| {
                        let r = db
                            .one(
                                "SELECT account, settings, secret FROM connections WHERE user_id = ? AND provider = ?",
                                &dumbslab_core::params![user.clone(), *app],
                            )
                            .unwrap()
                            .unwrap();
                        (r.str("account"), r.str("settings"), r.str("secret"))
                    })
                    .collect();
                (found, true)
            })
            .unwrap();
        let labels: Vec<&str> = after.iter().map(|(label, _, _)| label.as_str()).collect();
        assert_eq!(labels, ["acme.atlassian.net", "wiki.atlassian.net", "Trello", "@ada", "", ""]);
        assert_eq!(after[0].1, json!({ "site": "acme.atlassian.net", "cloud_id": "1324a887" }).to_string(), "Jira settings stay");
        assert_eq!(after[2].1, "{}", "Trello's member id and username go");
        assert_eq!(after[3].1, json!({ "login": "ada", "search_in": "user:ada" }).to_string(), "other apps are untouched");
        let kept: Vec<&String> = after.iter().map(|(_, _, secret)| secret).collect();
        assert_eq!(kept, secrets.iter().collect::<Vec<_>>(), "credentials stay as they are");
        // The connections still work, labeled by site.
        let list = h.ok("GET", "/api/v1/connections", None, &admin);
        let jira = list["apps"].as_array().unwrap().iter().find(|a| a["id"] == "jira").unwrap();
        assert_eq!(jira["connected"]["account"], "acme.atlassian.net");
    }

    #[test]
    fn monday_sign_in_lets_admins_install_on_the_way() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.cfg.connectors.apps.insert("monday".into(), OAuthApp { client_id: "mid".into(), client_secret: "msecret".into() });
        let url =
            h.ok("POST", "/api/v1/connections", Some(json!({ "app": "monday" })), &admin)["authorize_url"].as_str().unwrap().to_string();
        assert!(url.starts_with("https://auth.monday.com/oauth2/authorize?"), "{url}");
        let q = query_of(&url);
        assert_eq!((q["force_install_if_needed"].as_str(), q["code_challenge_method"].as_str()), ("true", "S256"));
    }

    #[test]
    fn atlassian_connections_keep_nothing_personal() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let user_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        h.cfg.connectors.apps.insert("jira".into(), OAuthApp { client_id: "atl".into(), client_secret: "atl-secret".into() });
        // Everything stored for a connection: the row, and the credential sealed in it.
        let stored = |h: &H, app: &str| {
            let row = h
                .store
                .with_tx(|db| {
                    let r = db
                        .one("SELECT account, settings, secret FROM connections WHERE provider = ?", &dumbslab_core::params![app])
                        .unwrap()
                        .unwrap();
                    ((r.str("account"), r.str("settings"), r.str("secret")), true)
                })
                .unwrap();
            let cred = connect::open("connector-key", &user_id, app, &row.2).unwrap();
            (row.0, row.1, format!("{} {:?} {:?}", cred.token, cred.refresh_token, cred.fields))
        };
        let personal = ["5b10ac8d82e05b22cc7d4ef5", "ada@acme.com", "Ada", "Lovelace", "5abbe4b7ddc1b351ef961414", "a.png"];

        // Signing in to Jira: only the sites are asked for, and only the site is kept.
        let url =
            h.ok("POST", "/api/v1/connections", Some(json!({ "app": "jira" })), &admin)["authorize_url"].as_str().unwrap().to_string();
        let state = query_of(&url)["state"].clone();
        let r = h.call("GET", &format!("/connect/callback?code=c&state={}", urlencoding::encode(&state)), None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &atlassian);
        assert!(matches!(&finish, Finish::Redirect(u) if u.ends_with("connected=jira")), "{finish:?}");
        assert!(!sent.iter().any(|c| c.url.ends_with("/me")), "{sent:?}");
        let (label, settings, sealed) = stored(&h, "jira");
        assert_eq!((label.as_str(), sealed.contains("atl-at")), ("acme.atlassian.net", true));
        for p in personal {
            assert!(!label.contains(p) && !settings.contains(p) && !sealed.contains(p), "{p} kept: {label} {settings} {sealed}");
        }

        // An API token: the person's answer only checks it. The email they typed stays sealed in
        // the credential, which Basic auth needs, and nowhere else.
        let token = json!({ "app": "confluence", "fields": { "site": "acme.atlassian.net", "email": "ada@acme.com", "token": "tok" } });
        let r = h.call("POST", "/api/v1/connections", Some(token), &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_: &HttpCall| {
            ok(json!({ "type": "known", "accountId": "5b10ac8d82e05b22cc7d4ef5", "email": "ada@acme.com", "displayName": "Ada Lovelace" }))
        });
        assert_eq!(filled(&r, finish)["connection"]["account"], "acme.atlassian.net");
        let (label, settings, sealed) = stored(&h, "confluence");
        assert!(sealed.contains("ada@acme.com"));
        for p in personal {
            assert!(!label.contains(p) && !settings.contains(p), "{p} kept: {label} {settings}");
            assert!(p == "ada@acme.com" || !sealed.contains(p), "{p} sealed: {sealed}");
        }

        // Trello keeps no username or member id either.
        let trello = json!({ "app": "trello", "fields": { "key": "k1", "token": "t1" } });
        let r = h.call("POST", "/api/v1/connections", Some(trello), &admin);
        let (finish, sent) = drive(&h, job_of(&r), &atlassian);
        assert_eq!(sent[0].url, "https://api.trello.com/1/members/me?fields=id");
        assert_eq!(filled(&r, finish)["connection"]["account"], "Trello");
        let (label, settings, sealed) = stored(&h, "trello");
        for p in personal {
            assert!(!label.contains(p) && !settings.contains(p) && !sealed.contains(p), "{p} kept: {label} {settings} {sealed}");
        }
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
    fn drive(h: &H, job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Finish, Vec<HttpCall>) {
        let (finish, sent, _) = drive_job(h, job, answer);
        (finish, sent)
    }

    /// Like `drive`, and also the effects the job left for the host to deliver (its webhooks).
    fn drive_job(h: &H, mut job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Finish, Vec<HttpCall>, Vec<Effect>) {
        let mut replies = vec![];
        let mut sent = vec![];
        for _ in 0..connect::MAX_STEPS {
            let (step, next) = h
                .store
                .with_tx(|db| {
                    let (step, _) = connect::guarded_step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now(), |_| None);
                    let ok = step.is_ok();
                    ((step, job.clone()), ok)
                })
                .unwrap();
            job = next;
            match step.unwrap() {
                Step::Done(f) => return (f, sent, job.take_effects()),
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

    /// An ID token's claims. Microsoft links accounts by `oid`, here one per `sub` unless `extra`
    /// gives one: like Microsoft's, the same for every app.
    fn claims(issuer: &str, sub: &str, email: &str, extra: Value) -> Value {
        let now = chrono::Utc::now().timestamp();
        let mut c = json!({ "iss": issuer, "aud": "app-id", "sub": sub, "oid": oid_of(sub), "email": email, "exp": now + 300, "iat": now, "name": "Mo Member" });
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    }

    /// A Microsoft object ID (a GUID) for a test account.
    fn oid_of(name: &str) -> String {
        let h = dumbslab_core::util::sha256_hex(name);
        format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
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

        // Slack needs its workspace, like Microsoft's tenant: otherwise anyone's Slack account would do.
        let r = h.call(
            "PATCH",
            "/api/v1/sso",
            Some(json!({ "provider": "slack", "client_id": "app-id", "client_secret": "s", "enabled": true })),
            &admin,
        );
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("`team`"), "{}", r.body);

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

    // -----------------------------------------------------------------------
    // Setting up with the server's own Google, Microsoft and Slack apps.

    const GOOGLE: &str = "https://accounts.google.com";
    const SLACK: &str = "https://slack.com";

    fn shared_apps() -> dumbslab_core::sso::SharedApps {
        let app = |id: &str| Some(connect::OAuthApp { client_id: format!("{id}-app"), client_secret: format!("{id}-secret") });
        dumbslab_core::sso::SharedApps { google: app("google"), microsoft: app("microsoft"), slack: app("slack"), callback_url: None }
    }

    /// A workspace whose server has its own Google, Microsoft and Slack apps, and no connector key:
    /// shared mode stores no secret. Its admin is ada@acme.test.
    fn shared_workspace() -> (H, Auth) {
        let mut h = H::new();
        let (admin, _) = h.setup();
        h.cfg.sso_apps = shared_apps();
        (h, admin)
    }

    /// Microsoft's discovery document for every organization's accounts: its issuer is a template.
    fn ms_organizations() -> Value {
        json!({
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
            "authorization_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
            "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
            "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        })
    }

    /// Where setting up `provider` starts, and its discovery document.
    fn setup_discovery(provider: &str) -> Value {
        match provider {
            "google" => discovery(GOOGLE),
            "microsoft" => ms_organizations(),
            _ => discovery(SLACK),
        }
    }

    fn cookie_of(auth: &Auth) -> String {
        match auth {
            Auth::Cookie(c) => format!("dumbslab_session={c}"),
            _ => unreachable!("a browser session"),
        }
    }

    /// Starts setting up in `admin`'s browser session; returns the provider's sign-in URL.
    fn start_setup(h: &H, admin: &Auth, body: Value) -> String {
        let provider = body["provider"].as_str().unwrap().to_string();
        let r = h.call("POST", "/api/v1/sso/setup", Some(body), admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(h, job_of(&r), &|_| ok(setup_discovery(&provider)));
        let expected = match provider.as_str() {
            "microsoft" => "https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration".to_string(),
            "google" => format!("{GOOGLE}/.well-known/openid-configuration"),
            _ => format!("{SLACK}/.well-known/openid-configuration"),
        };
        assert_eq!(sent[0].url, expected);
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        v["authorize_url"].as_str().unwrap().to_string()
    }

    /// The provider sends `browser` back from `url` with a code (or `error`, when given), and its
    /// token endpoint answers with an ID token with `id_claims` and the sign-in's nonce. Returns
    /// where the browser lands, the requests the job made, and the webhooks it left.
    fn finish_setup(h: &H, url: &str, browser: &Auth, mut id_claims: Value, error: Option<&str>) -> (Landing, Vec<HttpCall>, Vec<Effect>) {
        let q = query_of(url);
        if id_claims.get("nonce").is_none() {
            id_claims["nonce"] = json!(q["nonce"]);
        }
        let back = match error {
            Some(e) => format!("{e}&state={}", urlencoding::encode(&q["state"])),
            None => format!("code=the-code&state={}", urlencoding::encode(&q["state"])),
        };
        let cookies = match browser {
            Auth::Cookie(_) => vec![cookie_of(browser)],
            _ => vec![],
        };
        let r = h.send(&callback_request(&back, &cookies));
        if r.effects.is_empty() {
            return (land(&r, None), vec![], vec![]);
        }
        let id = jwt(&id_claims);
        let (finish, sent, effects) = drive_job(h, job_of(&r), &|c| tokens(c, &id));
        (land(&r, Some(finish)), sent, effects)
    }

    /// The admin's ID token from `provider`, for the server's own app.
    fn admin_token(provider: &str, extra: Value) -> Value {
        let issuer = match provider {
            "google" => GOOGLE.to_string(),
            "microsoft" => ms_issuer(),
            _ => SLACK.to_string(),
        };
        let mut c = claims(&issuer, "admin-sub", "ada@acme.test", extra);
        c["aud"] = json!(format!("{provider}-app"));
        c["name"] = json!("Ada Admin");
        c
    }

    fn organization(provider: &str) -> Value {
        match provider {
            "google" => json!({ "hd": "acme.test", "email_verified": true }),
            "microsoft" => json!({ "tid": TENANT, "xms_edov": true }),
            _ => json!({ "https://slack.com/team_id": "T0ACME", "email_verified": true }),
        }
    }

    const SETTINGS: &str = "https://kb.test/settings/sso";

    #[test]
    fn setting_up_by_signing_in_with_the_servers_own_apps() {
        for provider in ["google", "microsoft", "slack"] {
            let (h, admin) = shared_workspace();
            let ada = me(&h, &admin)["id"].as_str().unwrap().to_string();
            h.user(&admin, "mo@acme.test", "Mo", "member");
            h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.test/dumbslab", "events": ["sso.*"] })), &admin);
            let s = h.ok("GET", "/api/v1/sso", None, &admin);
            assert_eq!((s["available"].as_bool(), s["shared_providers"].clone()), (Some(false), json!(["google", "microsoft", "slack"])));

            let url = start_setup(&h, &admin, json!({ "provider": provider }));
            let q = query_of(&url);
            assert_eq!(
                (q["client_id"].as_str(), q["redirect_uri"].as_str()),
                (format!("{provider}-app").as_str(), "https://kb.test/sso/callback")
            );
            assert_eq!((q["scope"].as_str(), q["code_challenge_method"].as_str()), ("openid email profile", "S256"));
            match provider {
                "google" => assert_eq!((q["hd"].as_str(), q["prompt"].as_str()), ("*", "select_account")),
                "microsoft" => {
                    assert!(url.starts_with("https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?"), "{url}");
                    assert_eq!(q["prompt"], "select_account");
                }
                _ => assert!(!q.contains_key("team")),
            }
            // Nothing changes until the admin comes back.
            assert!(h.ok("GET", "/api/v1/sso", None, &admin)["provider"].is_null());

            let (landing, sent, hooks) = finish_setup(&h, &url, &admin, admin_token(provider, organization(provider)), None);
            // Slack confirms the admin's address, not that its domain is the organization's: it's
            // only suggested, until the admin allows it with one click.
            let outcome = if provider == "slack" { "domain_needed" } else { "done" };
            assert_eq!(landing.location, format!("{SETTINGS}?sso_setup={outcome}"), "{provider}: {}", landing.error());
            assert!(landing.session().is_none(), "setting up doesn't start another session");
            // The code went to the token endpoint with the server's own app.
            let form = query_of(&format!("?{}", sent[0].body.clone().unwrap()));
            assert_eq!(form["redirect_uri"], "https://kb.test/sso/callback");
            let basic = sent[0].headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone());
            if provider == "slack" {
                assert_eq!((form["client_id"].as_str(), form["client_secret"].as_str()), ("slack-app", "slack-secret"));
            } else {
                let expected =
                    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{provider}-app:{provider}-secret")));
                assert_eq!(basic.as_deref(), Some(expected.as_str()), "{provider}");
            }

            // On, for the admin's organization, with the toggles as they were.
            let s = h.ok("GET", "/api/v1/sso", None, &admin);
            assert_eq!(
                (s["active"].as_bool(), s["enabled"].as_bool(), s["shared"].as_bool(), s["provider"].as_str()),
                (Some(true), Some(true), Some(true), Some(provider)),
                "{s}"
            );
            assert_eq!((s["require_sso"].as_bool(), s["auto_provision"].as_bool()), (Some(false), Some(false)));
            assert_eq!((s["client_id"].as_str(), s["client_secret_set"].as_bool()), (Some(""), Some(false)));
            if provider == "slack" {
                assert_eq!((s["allowed_domains"].clone(), s["suggested_domain"].as_str()), (json!([]), Some("acme.test")));
                let allow = json!({ "domain": "acme.test", "suggestion_id": s["suggestion_id"] });
                let v = h.ok("POST", "/api/v1/sso/suggested-domain", Some(allow), &admin);
                assert!(v["suggested_domain"].is_null() && v["suggestion_id"].is_null(), "{v}");
            } else {
                assert!(s["suggested_domain"].is_null());
            }
            let s = h.ok("GET", "/api/v1/sso", None, &admin);
            assert_eq!(s["allowed_domains"], json!(["acme.test"]), "{provider}");
            let issuer = match provider {
                "google" => GOOGLE.to_string(),
                "microsoft" => {
                    assert_eq!(s["tenant"], TENANT);
                    ms_issuer()
                }
                _ => {
                    assert_eq!(s["team"], "T0ACME");
                    SLACK.to_string()
                }
            };
            assert_eq!(s["issuer"], issuer);
            assert!(!s.to_string().contains(&format!("{provider}-secret")));
            // The admin's own account is linked, and the admins' log and webhooks say so.
            let linked = h.ok("GET", "/api/v1/sso/identities?user=all", None, &admin);
            assert_eq!((linked["items"].as_array().unwrap().len(), linked["items"][0]["user"]["id"].as_str()), (1, Some(ada.as_str())));
            assert_eq!(links_logged(&h, &admin), vec![(ada.clone(), "setup".to_string())]);
            let events: Vec<String> = hooks
                .iter()
                .filter_map(|e| match e {
                    Effect::Webhook(d) => d.headers.iter().find(|(k, _)| k == "x-dumbslab-event").map(|(_, v)| v.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(events, vec!["sso.updated".to_string(), "sso.linked".to_string()], "{provider}");
            assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"]["url"], "https://kb.test/sso/start");

            // People sign in through the same app; Microsoft's sign-ins use the directory's own issuer.
            let s = start(&h, &issuer);
            assert_eq!(
                (s.query["client_id"].as_str(), s.query["redirect_uri"].as_str()),
                (format!("{provider}-app").as_str(), "https://kb.test/sso/callback")
            );
            let mut c = claims(&issuer, "sub-mo", "mo@acme.test", organization(provider));
            c["aud"] = json!(format!("{provider}-app"));
            let (landing, _) = come_back(&h, &s, c, &tokens);
            assert_eq!(me(&h, &landing.session().unwrap_or_else(|| panic!("{provider}: {}", landing.error())))["email"], "mo@acme.test");
        }
    }

    #[test]
    fn setting_up_needs_an_organization_account() {
        let (h, admin) = shared_workspace();
        let attempt = |provider: &str, extra: Value| {
            let url = start_setup(&h, &admin, json!({ "provider": provider }));
            finish_setup(&h, &url, &admin, admin_token(provider, extra), None).0
        };
        let nothing_saved = || assert!(h.ok("GET", "/api/v1/sso", None, &admin)["provider"].is_null());
        // A personal Google account has no Workspace domain.
        let landing = attempt("google", json!({ "email": "ada@gmail.com", "email_verified": true }));
        assert_eq!(
            (landing.location.as_str(), landing.error().as_str()),
            (format!("{SETTINGS}?sso_error=personal_account").as_str(), "personal_account")
        );
        nothing_saved();
        // Nor has a personal Microsoft account.
        let consumers = "9188040d-6c67-4c5b-b112-36a304b66dad";
        let mut personal = admin_token("microsoft", json!({ "tid": consumers }));
        personal["iss"] = json!(format!("https://login.microsoftonline.com/{consumers}/v2.0"));
        let url = start_setup(&h, &admin, json!({ "provider": "microsoft" }));
        assert_eq!(finish_setup(&h, &url, &admin, personal, None).0.error(), "personal_account");
        assert_eq!(attempt("microsoft", json!({})).error(), "personal_account");
        // A token whose issuer names another directory than its `tid`.
        let mut mixed = admin_token("microsoft", json!({ "tid": TENANT }));
        mixed["iss"] = json!("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0");
        let url = start_setup(&h, &admin, json!({ "provider": "microsoft" }));
        assert_eq!(finish_setup(&h, &url, &admin, mixed, None).0.error(), "invalid_token");
        // Slack's token must name the Slack workspace.
        assert_eq!(attempt("slack", json!({ "email_verified": true })).error(), "not_in_org");
        nothing_saved();
        // Microsoft directories that need an administrator's approval, and admins who say no.
        for (error, code) in [
            ("error=access_denied&error_description=AADSTS90094%3A+Admin+consent+is+required.", "admin_consent"),
            ("error=consent_required", "admin_consent"),
            ("error=access_denied&error_description=AADSTS65004%3A+User+declined+to+consent.", "denied"),
            ("error=server_error&error_description=%3Cb%3Eoops%3C%2Fb%3E", "provider_error"),
        ] {
            let url = start_setup(&h, &admin, json!({ "provider": "microsoft" }));
            let (landing, sent, _) = finish_setup(&h, &url, &admin, json!({}), Some(error));
            assert_eq!((landing.error(), sent.len()), (code.to_string(), 0), "{error}");
            assert!(!landing.location.contains("AADSTS") && !landing.location.contains("oops"), "{}", landing.location);
        }
        nothing_saved();

        // No email domain Microsoft vouches for: set up, and the admin is told to add one.
        let landing = attempt("microsoft", json!({ "tid": TENANT, "email_verified": true }));
        assert_eq!(landing.location, format!("{SETTINGS}?sso_setup=domain_needed"));
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!((s["active"].as_bool(), s["tenant"].as_str(), s["allowed_domains"].clone()), (Some(true), Some(TENANT), json!([])));
        let v = set_up(&h, &admin, json!({ "allowed_domains": ["acme.test"] }), &ms_issuer());
        assert_eq!(
            (v["allowed_domains"].clone(), v["shared"].as_bool(), v["check"]["ok"].as_bool()),
            (json!(["acme.test"]), Some(true), Some(true))
        );
        // Setting the same directory up again keeps the domains the admin added.
        let landing = attempt("microsoft", json!({ "tid": TENANT }));
        assert_eq!(landing.location, format!("{SETTINGS}?sso_setup=done"));
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &admin)["allowed_domains"], json!(["acme.test"]));

        // A free-mail address is never an allowed or suggested domain, whoever vouches for it.
        for email in
            ["ada@gmail.com", "ada@tutamail.com", "ada@tutanota.de", "ada@keemail.me", "ada@pm.me", "ada@yahoo.co.uk", "ada@fastmail.fm"]
        {
            for provider in ["slack", "microsoft"] {
                let url = start_setup(&h, &admin, json!({ "provider": provider, "replace": true }));
                let vouched = if provider == "slack" {
                    json!({ "https://slack.com/team_id": "T0OTHER", "email_verified": true })
                } else {
                    json!({ "tid": "00000000-0000-0000-0000-0000000000aa", "xms_edov": true })
                };
                let mut c = admin_token(provider, vouched);
                c["email"] = json!(email);
                if provider == "microsoft" {
                    c["iss"] = json!("https://login.microsoftonline.com/00000000-0000-0000-0000-0000000000aa/v2.0");
                }
                let landing = finish_setup(&h, &url, &admin, c, None).0;
                assert_eq!(landing.location, format!("{SETTINGS}?sso_setup=domain_needed"), "{provider} {email}: {}", landing.error());
                let s = h.ok("GET", "/api/v1/sso", None, &admin);
                assert_eq!((s["allowed_domains"].clone(), s["suggested_domain"].clone()), (json!([]), Value::Null), "{provider} {email}");
            }
        }
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!((s["provider"].as_str(), s["tenant"].as_str()), (Some("microsoft"), Some("00000000-0000-0000-0000-0000000000aa")));
    }

    #[test]
    fn only_the_admin_who_started_can_finish_setting_up() {
        let (mut h, admin) = shared_workspace();
        let (mo_id, mo_token) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let mo = sign_in(&h, "mo@acme.test", "password123");
        let (bo_id, _) = h.user(&admin, "bo@acme.test", "Bo", "admin");
        let bo = sign_in(&h, "bo@acme.test", "password123");
        let t = h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "agent", "scopes": ["read", "write", "admin"] })), &admin);
        let admin_token_auth = Auth::Bearer(t["token"].as_str().unwrap().to_string());
        // Admins only, from a signed-in browser, for a provider the server has an app for.
        for auth in [&mo, &mo_token] {
            assert_eq!(h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "google" })), auth).status, 403);
        }
        let r = h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "google" })), &admin_token_auth);
        assert_eq!(r.status, 403, "an API token can't come back from Google: {}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("shared: true"));
        assert_eq!(h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "okta" })), &admin).status, 400);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sso_requests"), 0);

        let saved = || h.ok("GET", "/api/v1/sso", None, &admin_token_auth)["provider"].as_str().map(str::to_string);
        let google = || admin_token("google", organization("google"));
        // Finishing in another person's browser, or another session of the admin's, or none.
        let other = sign_in(&h, "ada@acme.test", "correct horse");
        for browser in [&mo, &other, &Auth::None] {
            let url = start_setup(&h, &admin, json!({ "provider": "google" }));
            let (landing, sent, _) = finish_setup(&h, &url, browser, google(), None);
            assert_eq!((landing.location.as_str(), sent.len()), (format!("{SETTINGS}?sso_error=other_session").as_str(), 0));
        }
        assert_eq!(saved(), None);
        // A made-up or reused state.
        let r = h.send(&callback_request("code=c&state=acme.made-up", &[cookie_of(&admin)]));
        assert_eq!(land(&r, None).error(), "expired");
        let url = start_setup(&h, &admin, json!({ "provider": "google" }));
        let q = query_of(&url);
        let back = format!("code=c&state={}", urlencoding::encode(&q["state"]));
        assert!(!h.send(&callback_request(&back, &[cookie_of(&admin)])).effects.is_empty());
        assert_eq!(land(&h.send(&callback_request(&back, &[cookie_of(&admin)])), None).error(), "expired");
        // An admin who's demoted while signing in at Google (their session stays) can't finish.
        let url = start_setup(&h, &bo, json!({ "provider": "google" }));
        h.ok("PATCH", &format!("/api/v1/users/{bo_id}"), Some(json!({ "role": "member" })), &admin);
        let mut c = google();
        c["sub"] = json!("bo-sub");
        assert_eq!(finish_setup(&h, &url, &bo, c, None).0.error(), "not_admin");
        // Settings another admin changes meanwhile aren't overwritten.
        let url = start_setup(&h, &admin, json!({ "provider": "google" }));
        set_up(&h, &admin_token_auth, json!({ "provider": "slack", "shared": true, "team": "T0ACME" }), SLACK);
        assert_eq!(finish_setup(&h, &url, &admin, google(), None).0.error(), "expired");
        assert_eq!(saved().as_deref(), Some("slack"));
        // Signed out after Google answered, before it's saved.
        let url = start_setup(&h, &admin, json!({ "provider": "slack" }));
        let q = query_of(&url);
        let r = h.send(&callback_request(&format!("code=c&state={}", urlencoding::encode(&q["state"])), &[cookie_of(&admin)]));
        let keep = sign_in(&h, "ada@acme.test", "correct horse");
        assert_eq!(h.call("POST", "/api/v1/auth/logout", None, &admin).status, 200);
        let mut c = admin_token("slack", json!({ "https://slack.com/team_id": "T0OTHER", "email_verified": true }));
        c["nonce"] = json!(q["nonce"]);
        let id = jwt(&c);
        let (finish, _) = drive(&h, job_of(&r), &|call| tokens(call, &id));
        assert_eq!(land(&r, Some(finish)).error(), "other_session");
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &keep)["team"], "T0ACME");
        // An account at the provider that's someone else's here isn't taken over.
        h.store
            .with_tx(|db| {
                let r = db.execute(
                    "INSERT INTO sso_identities (id, user_id, issuer, subject, email, created_at, last_used_at) VALUES ('i1', ?, ?, 'admin-sub', 'mo@acme.test', '2026-01-01T00:00:00Z', NULL)",
                    &dumbslab_core::params![mo_id.clone(), GOOGLE],
                );
                (r, true)
            })
            .unwrap()
            .unwrap();
        let url = start_setup(&h, &keep, json!({ "provider": "google", "replace": true }));
        assert_eq!(finish_setup(&h, &url, &keep, google(), None).0.error(), "already_linked");
        assert_eq!(saved().as_deref(), Some("slack"));
        // A server without the app.
        h.cfg.sso_apps.google = None;
        let r = h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "google", "replace": true })), &keep);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (400, Some("sso_shared_unavailable")), "{}", r.body);
    }

    #[test]
    fn setting_up_replaces_your_own_app_only_when_asked() {
        let (mut h, admin) = workspace();
        h.cfg.sso_apps = shared_apps();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        okta(&h, &admin, json!({ "require_sso": true, "auto_provision": true }));
        let r = h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "google" })), &admin);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (409, Some("sso_configured")), "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("replace"));
        let url = start_setup(&h, &admin, json!({ "provider": "google", "replace": true }));
        // Okta still works until the admin is back.
        assert_eq!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"]["name"], "Okta");
        let (landing, _, _) = finish_setup(&h, &url, &admin, admin_token("google", organization("google")), None);
        assert_eq!(landing.location, format!("{SETTINGS}?sso_setup=done"));
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!((s["provider"].as_str(), s["issuer"].as_str(), s["shared"].as_bool()), (Some("google"), Some(GOOGLE), Some(true)));
        // The old app's secret is gone; the toggles stay as they were.
        assert_eq!((s["client_secret_set"].as_bool(), s["client_id"].as_str()), (Some(false), Some("")));
        assert_eq!((s["require_sso"].as_bool(), s["auto_provision"].as_bool()), (Some(true), Some(true)));
        let stored: String = h
            .store
            .with_tx(|db| (db.one("SELECT value FROM settings WHERE key = 'sso'", &[]).unwrap().unwrap().str("value"), true))
            .unwrap();
        assert!(!stored.contains("client_secret\":\"") && !stored.contains("shh"), "{stored}");
        // The same provider again needs no confirming; another one does.
        start_setup(&h, &admin, json!({ "provider": "google" }));
        assert_eq!(h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "slack" })), &admin).status, 409);
        // Going back to your own app forgets the shared one.
        let v = set_up(&h, &admin, json!({ "shared": false, "client_id": "own-app", "client_secret": "own-secret" }), GOOGLE);
        assert_eq!((v["shared"].as_bool(), v["client_secret_set"].as_bool(), v["active"].as_bool()), (Some(false), Some(true), Some(true)));
    }

    #[test]
    fn losing_the_servers_app_turns_sso_off_without_locking_anyone_out() {
        let (mut h, admin) = shared_workspace();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let url = start_setup(&h, &admin, json!({ "provider": "google" }));
        finish_setup(&h, &url, &admin, admin_token("google", organization("google")), None);
        set_up(&h, &admin, json!({ "require_sso": true }), GOOGLE);
        let login = |h: &H| {
            h.call("POST", "/api/v1/auth/login", Some(json!({ "email": "mo@acme.test", "password": "password123" })), &Auth::None).status
        };
        assert_eq!(login(&h), 403);

        h.cfg.sso_apps.google = None;
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!(
            (s["active"].as_bool(), s["enabled"].as_bool(), s["shared_app_missing"].as_bool(), s["shared_providers"].clone()),
            (Some(false), Some(true), Some(true), json!(["microsoft", "slack"])),
            "{s}"
        );
        assert_eq!(login(&h), 200, "Require SSO doesn't lock people out while SSO can't work");
        assert!(h.ok("GET", "/api/v1/auth/state", None, &Auth::None)["sso"].is_null());
        let r = h.call("GET", "/sso/start", None, &Auth::None);
        assert!(r.effects.is_empty() && land(&r, None).error() == "not_configured");
        // Saving it on says why; turning it off works.
        let r = h.call("PATCH", "/api/v1/sso", Some(json!({ "auto_provision": false })), &admin);
        assert_eq!(r.status, 400);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("own Google app any more"), "{}", r.body);
        set_up(&h, &admin, json!({ "enabled": false }), GOOGLE);
        // When the app is back, so is single sign-on.
        h.cfg.sso_apps = shared_apps();
        let v = set_up(&h, &admin, json!({ "enabled": true }), GOOGLE);
        assert_eq!((v["active"].as_bool(), v["shared_app_missing"].as_bool()), (Some(true), Some(false)));
        assert_eq!(login(&h), 403);
    }

    #[test]
    fn agents_set_up_shared_mode_with_update_sso() {
        let (mut h, admin) = shared_workspace();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let bad = |h: &H, body: Value| {
            let r = h.call("PATCH", "/api/v1/sso", Some(body), &admin);
            assert_eq!(r.status, 400, "{}", r.body);
            r.body["error"]["message"].as_str().unwrap().to_string()
        };
        assert!(bad(&h, json!({ "provider": "okta", "shared": true, "issuer": OKTA })).contains("google"));
        assert!(bad(&h, json!({ "provider": "slack", "shared": true, "client_id": "x" })).contains("leave out `client_id`"));
        assert!(bad(&h, json!({ "provider": "slack", "shared": true, "enabled": true })).contains("`team`"));
        // No connector key, so no app of your own.
        let r = h.call(
            "PATCH",
            "/api/v1/sso",
            Some(json!({ "provider": "okta", "issuer": OKTA, "client_id": "a", "client_secret": "s" })),
            &admin,
        );
        assert_eq!(r.status, 503);

        let body = json!({ "provider": "slack", "shared": true, "team": "T0ACME", "allowed_domains": ["acme.test"], "enabled": true });
        let v = set_up(&h, &admin, body, SLACK);
        assert_eq!(
            (v["active"].as_bool(), v["shared"].as_bool(), v["check"]["ok"].as_bool(), v["client_secret_set"].as_bool()),
            (Some(true), Some(true), Some(true), Some(false)),
            "{v}"
        );
        let s = start(&h, SLACK);
        assert_eq!((s.query["client_id"].as_str(), s.query["team"].as_str()), ("slack-app", "T0ACME"));
        let mut c = claims(SLACK, "sub-mo", "mo@acme.test", organization("slack"));
        c["aud"] = json!("slack-app");
        let (landing, _) = come_back(&h, &s, c, &tokens);
        assert!(landing.session().is_some(), "{}", landing.error());
        // Another provider means another app: shared mode doesn't carry over unasked (and this
        // server can't keep a secret for one of your own).
        let r = h.call(
            "PATCH",
            "/api/v1/sso",
            Some(json!({ "provider": "google", "allowed_domains": ["acme.test"], "enabled": true })),
            &admin,
        );
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (503, Some("sso_off")));
        h.cfg.sso_apps.microsoft = None;
        let r = h.call("PATCH", "/api/v1/sso", Some(json!({ "provider": "microsoft", "shared": true, "tenant": TENANT })), &admin);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (400, Some("sso_shared_unavailable")));
    }

    /// Signs in through `issuer` as `sub`, with Microsoft's `oid` and other claims in `extra`, for
    /// the app `aud`. Returns the person signed in as, or the error code.
    fn ms_sign_in(h: &H, aud: &str, sub: &str, email: &str, extra: Value) -> Result<String, String> {
        let issuer = ms_issuer();
        let s = start(h, &issuer);
        assert_eq!(s.query["client_id"], aud);
        let mut c = claims(&issuer, sub, email, extra);
        c["aud"] = json!(aud);
        let (landing, _) = come_back(h, &s, c, &tokens);
        match landing.session() {
            Some(session) => Ok(me(h, &session)["id"].as_str().unwrap().to_string()),
            None => Err(landing.error()),
        }
    }

    fn password(h: &H, email: &str) -> u16 {
        h.call("POST", "/api/v1/auth/login", Some(json!({ "email": email, "password": "password123" })), &Auth::None).status
    }

    #[test]
    fn microsoft_links_survive_switching_to_the_servers_app() {
        let (mut h, admin) = workspace();
        h.cfg.sso_apps = shared_apps();
        let (mo_id, _) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let own = json!({ "provider": "microsoft", "tenant": TENANT, "allowed_domains": ["acme.test"], "client_id": "app-id",
            "client_secret": "s", "enabled": true, "require_sso": true });
        set_up(&h, &admin, own, &ms_issuer());
        let mo_oid = oid_of("mo");
        // Mo's first sign-in, through the workspace's own app, matches their verified email.
        let first = ms_sign_in(&h, "app-id", "own-app-sub-mo", "mo@acme.test", json!({ "tid": TENANT, "oid": mo_oid, "xms_edov": true }));
        assert_eq!(first, Ok(mo_id.clone()));

        // The admin switches to DumbSlab's app. Microsoft gives every app its own `sub` for Mo.
        let url = start_setup(&h, &admin, json!({ "provider": "microsoft", "replace": true }));
        let (landing, _, _) = finish_setup(&h, &url, &admin, admin_token("microsoft", organization("microsoft")), None);
        assert_eq!(landing.location, format!("{SETTINGS}?sso_setup=done"));
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!(
            (s["shared"].as_bool(), s["require_sso"].as_bool(), s["require_sso_paused"].as_bool()),
            (Some(true), Some(true), Some(false))
        );
        // Same `oid`, new `sub`, and no xms_edov to match an email by: still Mo.
        let again = ms_sign_in(&h, "microsoft-app", "shared-app-sub-mo", "mo@acme.test", json!({ "tid": TENANT, "oid": mo_oid }));
        assert_eq!(again, Ok(mo_id.clone()));
        assert_eq!(password(&h, "mo@acme.test"), 403, "Require single sign-on is still on, and Mo isn't locked out");
        // And back to the workspace's own app.
        set_up(&h, &admin, json!({ "shared": false, "client_id": "app-id", "client_secret": "s" }), &ms_issuer());
        let back = ms_sign_in(&h, "app-id", "own-app-sub-mo", "mo@acme.test", json!({ "tid": TENANT, "oid": mo_oid }));
        assert_eq!(back, Ok(mo_id));
        // A Microsoft token without `oid` can't be linked by it.
        let mut c = json!({ "tid": TENANT, "xms_edov": true });
        c["oid"] = Value::Null;
        assert_eq!(ms_sign_in(&h, "app-id", "sub-zed", "zed@acme.test", c), Err("invalid_token".into()));
    }

    #[test]
    fn microsoft_links_made_by_sub_move_to_oid_or_pause_require_sso() {
        let (mut h, admin) = workspace();
        h.cfg.sso_apps = shared_apps();
        let (mo_id, _) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let (zed_id, _) = h.user(&admin, "zed@acme.test", "Zed", "member");
        let (bo_id, _) = h.user(&admin, "bo@acme.test", "Bo", "member");
        let issuer = ms_issuer();
        let own = json!({ "provider": "microsoft", "tenant": TENANT, "allowed_domains": ["acme.test"], "client_id": "app-id",
            "client_secret": "s", "enabled": true, "require_sso": true });
        set_up(&h, &admin, own, &issuer);
        // Links made before links were by `oid`: by the own app's `sub`.
        let legacy = |user: &str, sub: &str| {
            h.store
                .with_tx(|db| {
                    let r = db.execute(
                        "INSERT INTO sso_identities (id, user_id, issuer, subject, email, created_at, last_used_at) VALUES (?, ?, ?, ?, '', '2026-01-01T00:00:00Z', NULL)",
                        &dumbslab_core::params![format!("legacy-{sub}"), user, issuer.clone(), sub],
                    );
                    (r, true)
                })
                .unwrap()
                .unwrap();
        };
        let subjects = || -> Vec<String> {
            h.store
                .with_tx(|db| {
                    let rows = db.query("SELECT subject FROM sso_identities ORDER BY subject", &[]).unwrap();
                    (rows.iter().map(|r| r.str("subject")).collect(), true)
                })
                .unwrap()
        };
        legacy(&mo_id, "own-app-sub-mo");
        legacy(&zed_id, "own-app-sub-zed");
        // Through the same app, Mo's old link still works, and moves to Mo's `oid`.
        let mo = ms_sign_in(&h, "app-id", "own-app-sub-mo", "mo@acme.test", json!({ "tid": TENANT }));
        assert_eq!(mo, Ok(mo_id.clone()));
        assert_eq!(subjects(), vec![format!("oid:{}", oid_of("own-app-sub-mo")), "own-app-sub-zed".to_string()]);

        // Switching to DumbSlab's app: Zed's link can't follow (it's by the old app's `sub`), so it's
        // forgotten, and "Require single sign-on" is paused so Zed isn't locked out.
        let url = start_setup(&h, &admin, json!({ "provider": "microsoft", "replace": true }));
        finish_setup(&h, &url, &admin, admin_token("microsoft", organization("microsoft")), None);
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!(
            (s["require_sso"].as_bool(), s["require_sso_paused"].as_bool(), s["active"].as_bool()),
            (Some(false), Some(true), Some(true))
        );
        assert!(!subjects().contains(&"own-app-sub-zed".to_string()));
        let activity = h.ok("GET", "/api/v1/activity?limit=100", None, &admin);
        let updated = activity["items"].as_array().unwrap().iter().find(|e| e["event"] == "sso.updated").unwrap().clone();
        assert_eq!((updated["data"]["links_forgotten"].as_i64(), updated["data"]["require_sso_paused"].as_bool()), (Some(1), Some(true)));
        assert_eq!(password(&h, "zed@acme.test"), 200, "Zed can sign in with their password, and link again");
        // Mo's link moved to `oid`, so it carried over.
        let mo =
            ms_sign_in(&h, "microsoft-app", "shared-app-sub-mo", "mo@acme.test", json!({ "tid": TENANT, "oid": oid_of("own-app-sub-mo") }));
        assert_eq!(mo, Ok(mo_id));
        // Zed's verified email matches again, with no old link in the way.
        let zed = ms_sign_in(&h, "microsoft-app", "shared-app-sub-zed", "zed@acme.test", json!({ "tid": TENANT, "xms_edov": true }));
        assert_eq!(zed, Ok(zed_id));
        // A form re-sending its old checkbox, or an agent's plain `require_sso: true`, can't turn it
        // back on by accident; nor does re-sending `false` clear the note.
        let r = h.call("PATCH", "/api/v1/sso", Some(json!({ "require_sso": true, "auto_provision": false })), &admin);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (409, Some("sso_relink_pending")), "{}", r.body);
        let v = set_up(&h, &admin, json!({ "require_sso": false }), &issuer);
        assert_eq!((v["require_sso"].as_bool(), v["require_sso_paused"].as_bool()), (Some(false), Some(true)));
        assert_eq!(password(&h, "zed@acme.test"), 200);
        // Confirming that people linked again turns it back on and clears the note.
        let v = set_up(&h, &admin, json!({ "require_sso": true, "relinked": true }), &issuer);
        assert_eq!((v["require_sso"].as_bool(), v["require_sso_paused"].as_bool()), (Some(true), Some(false)));

        // The same when an agent switches apps with update_sso.
        legacy(&bo_id, "shared-app-sub-bo");
        let v = set_up(&h, &admin, json!({ "shared": false, "client_id": "app-2", "client_secret": "s2" }), &issuer);
        assert_eq!((v["require_sso"].as_bool(), v["require_sso_paused"].as_bool()), (Some(false), Some(true)), "{v}");
        assert_eq!(password(&h, "bo@acme.test"), 200);
        // Without anyone left to link again, "Require single sign-on" stays as it is.
        set_up(&h, &admin, json!({ "require_sso": true, "relinked": true }), &issuer);
        let v = set_up(&h, &admin, json!({ "shared": true }), &issuer);
        assert_eq!((v["require_sso"].as_bool(), v["require_sso_paused"].as_bool()), (Some(true), Some(false)), "{v}");
    }

    #[test]
    fn settings_changed_before_the_sign_in_starts_are_never_overwritten() {
        let (h, admin) = shared_workspace();
        let t = h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "agent", "scopes": ["read", "write", "admin"] })), &admin);
        let agent = Auth::Bearer(t["token"].as_str().unwrap().to_string());
        let changed = |finish: Finish| match finish {
            Finish::Fail(e) => (e.status, e.code),
            other => panic!("{other:?}"),
        };
        // Nothing to replace when setting up starts, so no `replace` asked; then, before the job
        // even reads Google's discovery document, another admin sets up Microsoft.
        let r = h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "google" })), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        set_up(&h, &agent, json!({ "provider": "microsoft", "shared": true, "tenant": TENANT }), &ms_issuer());
        let (finish, sent) = drive(&h, job_of(&r), &|_| ok(discovery(GOOGLE)));
        assert_eq!((changed(finish), sent.len()), ((409, "sso_changed"), 0));
        // Or while it's waiting for that document.
        let r = h.call("POST", "/api/v1/sso/setup", Some(json!({ "provider": "google", "replace": true })), &admin);
        let mut job = job_of(&r);
        let first = h.store.with_tx(|db| (connect::step(db, &h.cfg, &mut job, vec![], chrono::Utc::now()), true)).unwrap().unwrap();
        assert!(matches!(first, Step::Fetch(_)));
        set_up(&h, &agent, json!({ "allowed_domains": ["acme.test"] }), &ms_issuer());
        let second = h
            .store
            .with_tx(|db| (connect::step(db, &h.cfg, &mut job, vec![ok(discovery(GOOGLE))], chrono::Utc::now()), true))
            .unwrap()
            .unwrap();
        let Step::Done(finish) = second else { panic!("done") };
        assert_eq!(changed(finish), (409, "sso_changed"));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM sso_requests"), 0, "no sign-in was started");
        let s = h.ok("GET", "/api/v1/sso", None, &admin);
        assert_eq!((s["provider"].as_str(), s["allowed_domains"].clone()), (Some("microsoft"), json!(["acme.test"])));
    }

    #[test]
    fn allowing_a_suggested_domain_keeps_newer_settings() {
        let (h, admin) = shared_workspace();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let slack_setup = |team: &str, replace: bool| {
            let url = start_setup(&h, &admin, json!({ "provider": "slack", "replace": replace }));
            let c = admin_token("slack", json!({ "https://slack.com/team_id": team, "email_verified": true }));
            assert_eq!(finish_setup(&h, &url, &admin, c, None).0.location, format!("{SETTINGS}?sso_setup=domain_needed"));
            let s = h.ok("GET", "/api/v1/sso", None, &admin);
            assert_eq!(s["suggested_domain"], "acme.test");
            s["suggestion_id"].as_str().unwrap().to_string()
        };
        let allow = |id: &str, auth: &Auth| {
            h.call("POST", "/api/v1/sso/suggested-domain", Some(json!({ "domain": "acme.test", "suggestion_id": id })), auth)
        };
        let id = slack_setup("T0ACME", false);
        assert_eq!(allow(&id, &mo).status, 403, "admins only");
        // Another domain saved after the page loaded stays: the suggestion is added to the list as it is now.
        set_up(&h, &admin, json!({ "allowed_domains": ["other.test"] }), SLACK);
        let r = allow(&id, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(
            (r.body["allowed_domains"].clone(), r.body["suggested_domain"].clone()),
            (json!(["other.test", "acme.test"]), Value::Null)
        );
        let activity = h.ok("GET", "/api/v1/activity?limit=5", None, &admin).to_string();
        assert!(activity.contains("allowed acme.test for single sign-on"), "{activity}");
        // It's gone once allowed.
        assert_eq!(allow(&id, &admin).body["error"]["code"], "sso_suggestion_changed");

        // A tab still showing an old suggestion can't add it to a newer setup: another Slack
        // workspace, or another provider.
        let id = slack_setup("T0OLD", true);
        slack_setup("T0NEW", true);
        assert_eq!(allow(&id, &admin).body["error"]["code"], "sso_suggestion_changed");
        let id = slack_setup("T0NEW", false);
        let url = start_setup(&h, &admin, json!({ "provider": "google", "replace": true }));
        let c = admin_token("google", json!({ "hd": "beta.test", "email_verified": true }));
        finish_setup(&h, &url, &admin, c, None);
        let r = allow(&id, &admin);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (409, Some("sso_suggestion_changed")));
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &admin)["allowed_domains"], json!(["beta.test"]));
    }

    #[test]
    fn company_domains_are_never_mistaken_for_free_mail() {
        let (h, admin) = shared_workspace();
        // Google's hosted domain is Google's word: it's the organization's.
        let url = start_setup(&h, &admin, json!({ "provider": "google" }));
        let landing = finish_setup(&h, &url, &admin, admin_token("google", json!({ "hd": "live.abc.de", "email_verified": true })), None).0;
        assert_eq!(landing.location, format!("{SETTINGS}?sso_setup=done"), "{}", landing.error());
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &admin)["allowed_domains"], json!(["live.abc.de"]));
        // Microsoft's, with xms_edov.
        let url = start_setup(&h, &admin, json!({ "provider": "microsoft", "replace": true }));
        let mut c = admin_token("microsoft", organization("microsoft"));
        c["email"] = json!("ada@gmx.acme.com");
        assert_eq!(finish_setup(&h, &url, &admin, c, None).0.location, format!("{SETTINGS}?sso_setup=done"));
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &admin)["allowed_domains"], json!(["gmx.acme.com"]));
        // Slack's, suggested.
        let url = start_setup(&h, &admin, json!({ "provider": "slack", "replace": true }));
        let mut c = admin_token("slack", organization("slack"));
        c["email"] = json!("ada@mail.acme.co.uk");
        finish_setup(&h, &url, &admin, c, None);
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &admin)["suggested_domain"], "mail.acme.co.uk");
    }

    #[test]
    fn hosted_sign_ins_come_back_through_the_root_domain() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        h.cfg.base_url = Some("https://acme.kb.test".into());
        h.cfg.workspace = Some("acme".into());
        h.cfg.sso_apps = dumbslab_core::sso::SharedApps { callback_url: Some("https://kb.test/sso/callback".into()), ..shared_apps() };
        let url = start_setup(&h, &admin, json!({ "provider": "google" }));
        let q = query_of(&url);
        assert_eq!(q["redirect_uri"], "https://kb.test/sso/callback");
        assert!(q["state"].starts_with("acme.") && q["state"].len() > 30, "{}", q["state"]);
        let (landing, sent, _) = finish_setup(&h, &url, &admin, admin_token("google", organization("google")), None);
        assert_eq!(landing.location, "https://acme.kb.test/settings/sso?sso_setup=done");
        assert_eq!(query_of(&format!("?{}", sent[0].body.clone().unwrap()))["redirect_uri"], "https://kb.test/sso/callback");
        // People's sign-ins too.
        let s = start(&h, GOOGLE);
        assert!(s.query["state"].starts_with("acme.") && s.query["redirect_uri"] == "https://kb.test/sso/callback", "{:?}", s.query);
        let mut c = claims(GOOGLE, "sub-mo", "mo@acme.test", organization("google"));
        c["aud"] = json!("google-app");
        let (landing, sent) = come_back(&h, &s, c, &tokens);
        assert_eq!(landing.location, "https://acme.kb.test/p/abc", "{}", landing.error());
        assert_eq!(query_of(&format!("?{}", sent[0].body.clone().unwrap()))["redirect_uri"], "https://kb.test/sso/callback");
        // Your own app keeps the workspace's own redirect URI.
        assert_eq!(h.ok("GET", "/api/v1/sso", None, &admin)["redirect_uri"], "https://acme.kb.test/sso/callback");
    }
}

// ---------------------------------------------------------------------------
// Slack. The tests play Slack (signed requests, and canned answers from its API) and the host.

mod slack {
    use super::*;
    use dumbslab_core::connect::{self, Finish, HttpCall, HttpReply, Job, Step};
    use dumbslab_core::util::hmac_sha256_hex;

    const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    const TOKEN: &str = "xoxb-1-secret-bot-token";
    const REPLY_TO: &str = "https://hooks.slack.com/commands/T1/1234/abcXYZ";

    /// The job the host runs before answering (settings).
    fn job_of(r: &Res) -> Option<Job> {
        r.effects.iter().find_map(|e| match e {
            Effect::Connect(j) => Some(j.clone()),
            _ => None,
        })
    }

    /// The job the host runs after answering (Slack's commands and events).
    fn later_of(r: &Res) -> Option<Job> {
        assert!(job_of(r).is_none(), "Slack's requests never wait on a job");
        r.effects.iter().find_map(|e| match e {
            Effect::Background(j) => Some(j.clone()),
            _ => None,
        })
    }

    /// Runs a job with Slack's canned answers: how it finished, every call it made, and the
    /// effects it left for the host.
    fn drive(h: &H, mut job: Job) -> (Finish, Vec<HttpCall>, Vec<Effect>) {
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
                Step::Done(f) => return (f, sent, job.take_effects()),
                Step::Fetch(calls) => {
                    replies = calls.iter().map(slack_api).collect();
                    sent.extend(calls);
                }
            }
        }
        panic!("job didn't finish");
    }

    fn person(id: &str, email: &str, confirmed: bool, team: &str) -> HttpReply {
        let user = json!({ "id": id, "team_id": team, "deleted": false, "is_bot": false, "is_email_confirmed": confirmed,
            "profile": { "email": email, "real_name": id } });
        HttpReply { status: 200, body: json!({ "ok": true, "user": user }).to_string() }
    }

    /// Slack's API for the Slack workspace T1.
    fn slack_api(call: &HttpCall) -> HttpReply {
        let ok = |v: Value| HttpReply { status: 200, body: v.to_string() };
        let url = call.url.as_str();
        // A command's answer goes to its response_url, which needs no token.
        if url.starts_with(REPLY_TO) {
            assert!(!call.headers.iter().any(|(k, _)| k == "authorization"), "the bot token went to the response_url");
            return HttpReply { status: 200, body: "ok".into() };
        }
        assert!(call.headers.iter().any(|(k, v)| k == "authorization" && v == &format!("Bearer {TOKEN}")), "{url} without the bot token");
        if url == "https://slack.com/api/auth.test" {
            return ok(json!({ "ok": true, "team": "Acme Slack", "team_id": "T1", "user_id": "UBOT", "bot_id": "B1" }));
        }
        if let Some(user) = url.strip_prefix("https://slack.com/api/users.info?user=") {
            return match user {
                "UADA" => person("UADA", "ADA@acme.test", true, "T1"),
                "UMO" => person("UMO", "mo@acme.test", true, "T1"),
                "UVI" => person("UVI", "vi@acme.test", true, "T1"),
                "UGONE" => person("UGONE", "gone@acme.test", true, "T1"),
                "UNEW" => person("UNEW", "mo@acme.test", false, "T1"),
                "UOUT" => person("UOUT", "mo@acme.test", true, "T9"),
                "USTRANGER" => person("USTRANGER", "someone@else.test", true, "T1"),
                _ => ok(json!({ "ok": false, "error": "user_not_found" })),
            };
        }
        if url == "https://slack.com/api/chat.unfurl" {
            return ok(json!({ "ok": true }));
        }
        if url == "https://slack.com/api/chat.postMessage" {
            let body: Value = serde_json::from_str(call.body.as_deref().unwrap()).unwrap();
            return match body["channel"].as_str() {
                Some("GPRIVATE1") => ok(json!({ "ok": false, "error": "not_in_channel" })),
                _ => ok(json!({ "ok": true, "ts": "1.2" })),
            };
        }
        HttpReply { status: 404, body: "{}".into() }
    }

    /// A workspace with Slack connected, and its admin Ada.
    pub(super) fn connected() -> (H, Auth) {
        let mut h = H::new();
        let (admin, _) = h.setup();
        h.cfg.connectors.key = Some("connector-key".into());
        let r = h.call("PATCH", "/api/v1/slack", Some(json!({ "bot_token": TOKEN, "signing_secret": SECRET })), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, _, _) = drive(&h, job_of(&r).expect("a job that checks the token"));
        let Finish::Fill(v) = finish else { panic!("{finish:?}") };
        assert_eq!((v["connected"].as_bool(), v["slack_workspace"].as_str()), (Some(true), Some("Acme Slack")), "{v}");
        (h, admin)
    }

    fn signed_at(path: &str, body: &str, content_type: &str, at: i64, secret: &str) -> Request {
        let signature = format!("v0={}", hmac_sha256_hex(secret, &format!("v0:{at}:{body}")));
        Request {
            method: "POST".into(),
            path: path.into(),
            headers: vec![
                ("content-type".into(), content_type.into()),
                ("x-slack-request-timestamp".into(), at.to_string()),
                ("x-slack-signature".into(), signature),
            ],
            body: body.as_bytes().to_vec(),
            origin: "https://kb.test".into(),
            ..Default::default()
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn command_body_to(user: &str, text: &str, reply_to: &str) -> String {
        format!(
            "token=x&team_id=T1&channel_id=C1&user_id={user}&user_name=x&command=%2Fdumbslab&text={}&response_url={}&trigger_id={}",
            urlencoding::encode(text),
            urlencoding::encode(reply_to),
            dumbslab_core::util::new_id()
        )
    }

    fn command_body(user: &str, text: &str) -> String {
        command_body_to(user, text, REPLY_TO)
    }

    /// The answer a job posted to the command's response_url.
    fn posted_answer(calls: &[HttpCall]) -> Value {
        let last = calls.last().expect("an answer");
        assert_eq!((last.method, last.url.as_str()), ("POST", REPLY_TO), "{calls:?}");
        serde_json::from_str(last.body.as_deref().unwrap()).unwrap()
    }

    /// Sends `/dumbslab {text}` as a Slack user. The reply: Slack's answer when there's one right
    /// away, or what the job posted to the response_url afterwards.
    fn command(h: &H, user: &str, text: &str) -> Value {
        let r = h.send(&signed_at("/slack/commands", &command_body(user, text), "application/x-www-form-urlencoded", now(), SECRET));
        assert_eq!(r.status, 200, "{}", r.body);
        match later_of(&r) {
            None => r.body,
            Some(job) => {
                assert_eq!(r.body, json!(""), "acknowledged with an empty answer");
                posted_answer(&drive(h, job).1)
            }
        }
    }

    fn event(links: &[&str], user: &str, source: &str) -> String {
        let links: Vec<Value> = links.iter().map(|u| json!({ "url": u, "domain": "kb.test" })).collect();
        json!({
            "token": "x", "team_id": "T1", "api_app_id": "A1", "type": "event_callback",
            "event_id": format!("Ev{}", dumbslab_core::util::new_id()), "event_time": now(),
            "event": { "type": "link_shared", "channel": "C1", "is_bot_user_member": true, "user": user, "message_ts": "123.456",
                       "unfurl_id": "U123", "source": source, "links": links },
        })
        .to_string()
    }

    /// Shares links in Slack; the `chat.unfurl` call DumbSlab makes, if any.
    fn share(h: &H, links: &[&str], user: &str, source: &str) -> Option<Value> {
        let r = h.send(&signed_at("/slack/events", &event(links, user, source), "application/json", now(), SECRET));
        // Acknowledged at once; the preview follows.
        assert_eq!((r.status, &r.body), (200, &json!({ "ok": true })));
        let (_, calls, _) = drive(h, later_of(&r)?);
        calls.iter().find(|c| c.url.ends_with("/chat.unfurl")).map(|c| serde_json::from_str(c.body.as_deref().unwrap()).unwrap())
    }

    fn text_of(reply: &Value) -> String {
        reply.to_string()
    }

    pub(super) fn slack_messages(effects: &[Effect]) -> Vec<Value> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Webhook(d) if d.url == "https://slack.com/api/chat.postMessage" => {
                    assert!(d.headers.contains(&("authorization".into(), format!("Bearer {TOKEN}"))));
                    Some(serde_json::from_str(&d.body).unwrap())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn slack_requests_must_be_signed_fresh_and_new() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let verification = json!({ "token": "x", "challenge": "3eZbrw1aBm2rZgRNFdxV", "type": "url_verification" }).to_string();
        // Before anyone connects Slack, nothing answers.
        let r = h.send(&signed_at("/slack/events", &verification, "application/json", now(), SECRET));
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (404, Some("slack_off")));

        // A signing secret alone is enough for Slack to check the events URL.
        h.cfg.connectors.key = Some("connector-key".into());
        h.ok("PATCH", "/api/v1/slack", Some(json!({ "signing_secret": SECRET })), &admin);
        let r = h.send(&signed_at("/slack/events", &verification, "application/json", now(), SECRET));
        assert_eq!((r.status, &r.body), (200, &json!({ "challenge": "3eZbrw1aBm2rZgRNFdxV" })));
        assert_eq!(r.header("cache-control"), Some("no-store"));

        // The same request again is refused: each signature is good once.
        let other = verification.replace("3eZbrw1aBm2rZgRNFdxV", "another-challenge");
        let again = signed_at("/slack/events", &other, "application/json", now(), SECRET);
        assert_eq!(h.send(&again).status, 200);
        let replayed = h.send(&again);
        assert_eq!((replayed.status, replayed.body["error"]["code"].as_str()), (401, Some("replayed")));

        let code = |req: &Request| {
            let r = h.send(req);
            (r.status, r.body["error"]["code"].as_str().unwrap_or_default().to_string())
        };
        let mut unsigned = signed_at("/slack/events", &verification, "application/json", now(), SECRET);
        unsigned.headers.retain(|(k, _)| k != "x-slack-signature");
        assert_eq!(code(&unsigned), (401, "unsigned".into()));
        assert_eq!(
            code(&signed_at("/slack/events", &verification, "application/json", now(), "another-secret")),
            (401, "bad_signature".into())
        );
        let mut tampered = signed_at("/slack/events", &verification, "application/json", now(), SECRET);
        tampered.body = verification.replace("3eZbrw1aBm2rZgRNFdxV", "something-else").into_bytes();
        assert_eq!(code(&tampered), (401, "bad_signature".into()));
        assert_eq!(
            code(&signed_at("/slack/events", &verification, "application/json", now() - 301, SECRET)),
            (401, "stale_request".into())
        );
        assert_eq!(
            code(&signed_at("/slack/events", &verification, "application/json", now() + 301, SECRET)),
            (401, "stale_request".into())
        );
        // Slack only POSTs, keeps its requests small, and reaches only these two paths.
        let mut get = signed_at("/slack/events", "", "application/json", now(), SECRET);
        get.method = "GET".into();
        assert_eq!(code(&get).0, 405);
        assert_eq!(code(&signed_at("/slack/other", &verification, "application/json", now(), SECRET)).0, 404);
        assert_eq!(dumbslab_core::http::body_limit("/slack/events"), 64 * 1024);
        let big = format!("{{\"type\":\"url_verification\",\"challenge\":\"{}\"}}", "x".repeat(70 * 1024));
        assert_eq!(code(&signed_at("/slack/events", &big, "application/json", now(), SECRET)).0, 413);
        // No session or token gets past the signature check.
        let mut with_cookie = unsigned.clone();
        let Auth::Cookie(c) = &admin else { unreachable!() };
        with_cookie.headers.push(("cookie".into(), format!("dumbslab_session={c}")));
        assert_eq!(code(&with_cookie).0, 401);
    }

    /// Slack sends an event again when an answer was slow, signed anew; it's handled once.
    #[test]
    fn slack_events_are_handled_once() {
        let (h, admin) = connected();
        let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Retried", "status": "published" })), &admin);
        let url = post["url"].as_str().unwrap().to_string();
        let body = event(&[&url], "UADA", "conversations_history");
        let first = h.send(&signed_at("/slack/events", &body, "application/json", now(), SECRET));
        assert!(later_of(&first).is_some());
        let retry = h.send(&signed_at("/slack/events", &body, "application/json", now() + 1, SECRET));
        assert_eq!((retry.status, later_of(&retry).is_none()), (200, true), "{}", retry.body);
    }

    #[test]
    fn slack_search_shows_only_what_the_person_can_see() {
        let (h, admin) = connected();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let (gone_id, _) = h.user(&admin, "gone@acme.test", "Gone", "member");
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Leadership", "visibility": "private" })), &admin);
        let tid = topic["id"].as_str().unwrap();
        h.ok(
            "POST",
            "/api/v1/posts",
            Some(json!({ "title": "Rotation for everyone", "content": "The on-call rotation & a < b", "status": "published" })),
            &admin,
        );
        h.ok(
            "POST",
            "/api/v1/posts",
            Some(json!({ "title": "Rotation salaries", "content": "Private rotation pay", "status": "published", "topic_ids": [tid] })),
            &admin,
        );
        h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Rotation draft by Ada", "content": "rotation" })), &admin);

        // Mo sees the public post only, in a reply only Mo sees.
        let reply = command(&h, "UMO", "search rotation");
        assert_eq!(reply["response_type"], "ephemeral", "{reply}");
        let text = text_of(&reply);
        assert!(text.contains("Rotation for everyone"), "{text}");
        assert!(text.contains("rotation &amp; a &lt; b"), "content is escaped: {text}");
        assert!(!text.contains("salaries") && !text.contains("draft by Ada"), "{text}");
        // Ada, an admin, sees the private post and her own draft.
        let text = text_of(&command(&h, "UADA", "search rotation"));
        assert!(text.contains("Rotation salaries") && text.contains("Rotation draft by Ada"), "{text}");
        // Once Mo joins the private topic, Mo finds its post.
        h.ok("POST", &format!("/api/v1/topics/{tid}/members"), Some(json!({ "user": "mo@acme.test" })), &admin);
        assert!(text_of(&command(&h, "UMO", "search rotation")).contains("Rotation salaries"));

        // Nobody DumbSlab can match gets anything from the workspace.
        for user in ["USTRANGER", "UOUT", "UNKNOWN"] {
            let text = text_of(&command(&h, user, "search rotation"));
            assert!(text.contains("isn't linked to anyone in Acme"), "{user}: {text}");
            assert!(!text.contains("Rotation"), "{user}: {text}");
        }
        let text = text_of(&command(&h, "UNEW", "search rotation"));
        assert!(text.contains("hasn't confirmed your email") && !text.contains("Rotation"), "{text}");
        // A deactivated person is no one either.
        h.ok("PATCH", &format!("/api/v1/users/{gone_id}"), Some(json!({ "deactivated": true })), &admin);
        assert!(text_of(&command(&h, "UGONE", "search rotation")).contains("isn't linked"));

        // Anything else gets help; searching needs words.
        assert!(text_of(&command(&h, "UMO", "")).contains("search &lt;words&gt;"));
        assert!(text_of(&command(&h, "UMO", "what is this")).contains("new &lt;title&gt;"));
        assert!(text_of(&command(&h, "UMO", "search")).contains("Add the words"));
        assert!(text_of(&command(&h, "UMO", "search nothingmatchesthis")).contains("No posts you can see match"));
    }

    #[test]
    fn slack_drafts_belong_to_the_person() {
        let (h, admin) = connected();
        let (mo_id, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        h.user(&admin, "vi@acme.test", "Vi", "viewer");
        h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.test/in", "events": ["post.created"] })), &admin);

        let r = h.send(&signed_at(
            "/slack/commands",
            &command_body("UMO", "new Onboarding <!channel>"),
            "application/x-www-form-urlencoded",
            now(),
            SECRET,
        ));
        let (_, calls, effects) = drive(&h, later_of(&r).unwrap());
        let text = text_of(&posted_answer(&calls));
        assert!(text.contains("Started a draft") && text.contains("Onboarding &lt;!channel&gt;"), "{text}");
        let drafts = h.ok("GET", "/api/v1/posts?status=draft&author=me", None, &mo);
        let draft = drafts["items"].as_array().unwrap().iter().find(|p| p["title"] == "Onboarding <!channel>").expect("Mo's draft").clone();
        assert_eq!((draft["author"]["id"].as_str(), draft["status"].as_str()), (Some(mo_id.as_str()), Some("draft")));
        assert!(text.contains(draft["id"].as_str().unwrap()), "the reply links the draft: {text}");
        // The draft's webhooks go out like any other change's.
        assert!(effects.iter().any(|e| matches!(e, Effect::Webhook(d) if d.url == "https://hooks.test/in")), "{effects:?}");
        // Activity shows it came from Slack.
        let activity = h.ok("GET", "/api/v1/activity?event=post.created", None, &admin);
        assert_eq!(activity["items"][0]["via"], "slack", "{activity}");

        // A viewer can't write, and is told so.
        let text = text_of(&command(&h, "UVI", "new Not allowed"));
        assert!(text.contains("member role"), "{text}");
        let all = h.ok("GET", "/api/v1/search?q=allowed", None, &admin);
        assert!(all["items"].as_array().unwrap().is_empty(), "nothing was created");
        assert!(text_of(&command(&h, "UMO", "new")).contains("Add the draft's title"));
    }

    #[test]
    fn slack_previews_only_posts_everyone_can_see() {
        let (h, admin) = connected();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let private = h.ok(
            "POST",
            "/api/v1/topics",
            Some(json!({ "name": "Leadership", "visibility": "private", "members": ["mo@acme.test"] })),
            &admin,
        );
        let public_topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin);
        let public = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Expenses <!here>", "content": "File them & smile", "status": "published", "topic_ids": [public_topic["id"]] })), &admin);
        let secret = h.ok(
            "POST",
            "/api/v1/posts",
            Some(json!({ "title": "Layoff plan", "content": "secret", "status": "published", "topic_ids": [private["id"]] })),
            &admin,
        );
        let draft = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Mo's draft", "content": "draft" })), &mo);
        let (pu, su, du) = (public["url"].as_str().unwrap(), secret["url"].as_str().unwrap(), draft["url"].as_str().unwrap());

        // Mo can see all three, but Slack shows previews to the whole channel: only the public one.
        let call = share(&h, &[pu, su, du, "https://elsewhere.test/p/abc"], "UMO", "conversations_history").expect("a chat.unfurl call");
        let unfurls = call["unfurls"].as_object().unwrap();
        assert_eq!(unfurls.keys().collect::<Vec<_>>(), vec![pu], "{call}");
        let shown = call.to_string();
        assert!(
            shown.contains("Expenses &lt;!here&gt;") && shown.contains("File them &amp; smile") && shown.contains("Handbook"),
            "{shown}"
        );
        assert!(!shown.contains("Layoff") && !shown.contains("Leadership") && !shown.contains("Mo's draft"), "{shown}");
        assert_eq!((call["unfurl_id"].as_str(), call["source"].as_str()), (Some("U123"), Some("conversations_history")));

        // Someone DumbSlab can't match gets no preview, not even a title.
        assert!(share(&h, &[pu], "USTRANGER", "composer").is_none());
        assert!(share(&h, &[pu], "UNEW", "composer").is_none());
        // A private post gets none, whoever shares it.
        assert!(share(&h, &[su], "UADA", "composer").is_none());

        // Admins can turn previews off.
        h.ok("PATCH", "/api/v1/slack", Some(json!({ "unfurls": false })), &admin);
        assert!(share(&h, &[pu], "UMO", "composer").is_none());
    }

    #[test]
    fn slack_channels_hear_about_posts_with_escaped_text() {
        let (h, admin) = connected();
        let private = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Leadership", "visibility": "private" })), &admin);
        let eng = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Engineering" })), &admin);
        let sub_private =
            h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Incidents", "visibility": "private", "parent_id": eng["id"] })), &admin);
        let all = h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0ALLPOSTS", "updated_posts": true })), &admin);
        h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0LEADERS1", "topic_id": private["id"] })), &admin);
        h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0ENGINEERING", "topic_id": eng["id"] })), &admin);
        assert_eq!(h.call("POST", "/api/v1/slack/channels", Some(json!({ "channel": "general chat" })), &admin).status, 400);
        assert_eq!(
            h.call("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0XXXXXXXX", "topic_id": "nope" })), &admin).status,
            404
        );

        let to =
            |r: &Res| -> Vec<String> { slack_messages(&r.effects).iter().map(|m| m["channel"].as_str().unwrap().to_string()).collect() };
        // A published post everyone can see goes to the channel for every post, with its text escaped.
        let r = h.call(
            "POST",
            "/api/v1/posts",
            Some(json!({ "title": "<!channel> & <@U1> ship it", "content": "Deploy <https://evil.test|here>", "status": "published", "topic_ids": [eng["id"]] })),
            &admin,
        );
        assert_eq!(to(&r), vec!["C0ALLPOSTS", "C0ENGINEERING"]);
        let message = &slack_messages(&r.effects)[0];
        let shown = message.to_string();
        assert!(!shown.contains("<!channel>") && !shown.contains("<@U1>") && !shown.contains("<https://evil.test"), "{shown}");
        assert!(message["text"].as_str().unwrap().contains("&lt;!channel&gt; &amp; &lt;@U1&gt; ship it"), "{message}");
        assert_eq!((message["parse"].as_str(), message["unfurl_links"].as_bool()), (Some("none"), Some(false)));
        assert!(message["blocks"].as_array().unwrap().iter().all(|b| b.to_string().contains("\"verbatim\":true")), "{message}");
        let id = r.body["id"].as_str().unwrap().to_string();
        assert!(shown.contains(&format!("https://kb.test/p/{id}/")), "it links the post: {shown}");

        // A private topic's post goes only where an admin picked that topic.
        let r = h.call(
            "POST",
            "/api/v1/posts",
            Some(json!({ "title": "Board notes", "status": "published", "topic_ids": [private["id"]] })),
            &admin,
        );
        assert_eq!(to(&r), vec!["C0LEADERS1"]);
        assert!(slack_messages(&r.effects)[0].to_string().contains("Leadership"));
        // A private subtopic wasn't picked with its parent.
        let r = h.call(
            "POST",
            "/api/v1/posts",
            Some(json!({ "title": "Outage", "status": "published", "topic_ids": [sub_private["id"]] })),
            &admin,
        );
        assert!(to(&r).is_empty(), "{:?}", to(&r));

        // Drafts stay quiet until they're published.
        let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "Later", "topic_ids": [eng["id"]] })), &admin);
        assert!(to(&r).is_empty());
        let later = r.body["id"].as_str().unwrap().to_string();
        let r =
            h.call("PATCH", &format!("/api/v1/posts/{later}"), Some(json!({ "status": "published", "content": "Now with words" })), &admin);
        assert_eq!(to(&r), vec!["C0ALLPOSTS", "C0ENGINEERING"], "one message per channel, even with an edit");
        assert!(slack_messages(&r.effects)[0].to_string().contains("Published by Ada Admin"));
        // Updates go only where they're wanted.
        let r = h.call("PATCH", &format!("/api/v1/posts/{later}"), Some(json!({ "content": "Edited" })), &admin);
        assert_eq!(to(&r), vec!["C0ALLPOSTS"]);
        assert!(slack_messages(&r.effects)[0].to_string().contains("Updated by Ada Admin"));
        h.ok("PATCH", &format!("/api/v1/slack/channels/{}", all["id"].as_str().unwrap()), Some(json!({ "updated_posts": false })), &admin);
        assert!(to(&h.call("PATCH", &format!("/api/v1/posts/{later}"), Some(json!({ "content": "Again" })), &admin)).is_empty());

        // A bulk import sends a few messages per channel, not hundreds.
        let docs: Vec<Value> = (0..20).map(|i| json!({ "title": format!("Imported {i}"), "content": "x" })).collect();
        let r = h.call("POST", "/api/v1/import", Some(json!({ "documents": docs })), &admin);
        assert_eq!(to(&r), vec!["C0ALLPOSTS"; 3]);

        // The test message reports whether Slack took it.
        let test = |channel: &str| {
            let channels = h.ok("GET", "/api/v1/slack", None, &admin)["channels"].clone();
            let id = channels.as_array().unwrap().iter().find(|c| c["channel"] == channel).unwrap()["id"].as_str().unwrap().to_string();
            let r = h.call("POST", &format!("/api/v1/slack/channels/{id}/test"), None, &admin);
            assert_eq!(r.status, 200, "{}", r.body);
            drive(&h, job_of(&r).unwrap()).0
        };
        assert!(matches!(test("C0ALLPOSTS"), Finish::Fill(ref v) if v["ok"] == true));
        let private_channel =
            h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "GPRIVATE1", "topic_id": private["id"] })), &admin)["id"]
                .clone();
        assert!(matches!(test("GPRIVATE1"), Finish::Fail(ref e) if e.message.contains("/invite @dumbslab")));
        h.ok("DELETE", &format!("/api/v1/slack/channels/{}", private_channel.as_str().unwrap()), None, &admin);

        // Without the bot token, nothing goes to Slack.
        h.ok("DELETE", "/api/v1/slack", None, &admin);
        let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "Quiet", "status": "published" })), &admin);
        assert!(to(&r).is_empty());
    }

    /// Slack drops a command's answer after three seconds: DumbSlab acknowledges at once, asks
    /// Slack who's asking afterwards, and posts the answer to the command's response_url.
    #[test]
    fn slack_commands_answer_at_once_and_reply_at_response_url() {
        let (h, admin) = connected();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Onboarding guide", "status": "published" })), &admin);
        let form = "application/x-www-form-urlencoded";

        // The answer: empty, before anything asks Slack. One job runs after it.
        let r = h.send(&signed_at("/slack/commands", &command_body("UMO", "search onboarding"), form, now(), SECRET));
        assert_eq!((r.status, &r.body), (200, &json!("")));
        assert_eq!(r.effects.len(), 1, "{:?}", r.effects);
        let (_, calls, _) = drive(&h, later_of(&r).expect("a job for after the answer"));
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0].url, "https://slack.com/api/users.info?user=UMO");
        assert!(calls[1].headers.contains(&("content-type".into(), "application/json; charset=utf-8".into())));
        let answer = posted_answer(&calls);
        assert_eq!(answer["response_type"], "ephemeral");
        assert!(text_of(&answer).contains("Onboarding guide"), "{answer}");
        // Someone DumbSlab can't match hears so at the response_url too.
        let r = h.send(&signed_at("/slack/commands", &command_body("USTRANGER", "search onboarding"), form, now(), SECRET));
        let text = text_of(&posted_answer(&drive(&h, later_of(&r).unwrap()).1));
        assert!(text.contains("isn't linked") && !text.contains("Onboarding"), "{text}");

        // An answer goes only to Slack's own hosts: anything else is refused before any job.
        for bad in [
            "https://evil.test/commands/T1/1/x",
            "http://hooks.slack.com/commands/T1/1/x",
            "https://hooks.slack.com.evil.test/commands/T1/1/x",
            "https://evil.test/hooks.slack.com/commands/T1/1/x",
            "https://hooks.slack.com:8443/commands/T1/1/x",
            "https://user@hooks.slack.com/commands/T1/1/x",
            "https://hooks.slack.com/commands/T1/1/x?to=https://evil.test",
            "https://hooks.slack.com/services/T1/B1/x",
            "https://hooks.slack.com/commands/../../services/x",
            "",
        ] {
            let r = h.send(&signed_at("/slack/commands", &command_body_to("UMO", "search onboarding", bad), form, now(), SECRET));
            assert_eq!(r.status, 200, "{bad}");
            assert!(r.effects.is_empty(), "{bad}: {:?}", r.effects);
            assert!(text_of(&r.body).contains("reply address"), "{bad}: {}", r.body);
        }
        // GovSlack's hooks host is Slack's too.
        let gov = "https://hooks.slack-gov.com/commands/T1/1/x";
        let r = h.send(&signed_at("/slack/commands", &command_body_to("UMO", "search onboarding", gov), form, now(), SECRET));
        assert!(later_of(&r).is_some());

        // Events are acknowledged at once too; the preview follows.
        let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Shared", "status": "published" })), &admin);
        let body = event(&[post["url"].as_str().unwrap()], "UMO", "conversations_history");
        let r = h.send(&signed_at("/slack/events", &body, "application/json", now(), SECRET));
        assert_eq!((r.status, &r.body, r.effects.len()), (200, &json!({ "ok": true }), 1));
        let (_, calls, _) = drive(&h, later_of(&r).unwrap());
        assert_eq!(
            calls.iter().map(|c| c.url.as_str()).collect::<Vec<_>>(),
            vec!["https://slack.com/api/users.info?user=UMO", "https://slack.com/api/chat.unfurl"]
        );
    }

    /// Several mappings can name one Slack channel: it hears about each post once, and the
    /// per-request limit is the channel's.
    #[test]
    fn slack_channels_hear_about_each_post_once() {
        let (h, admin) = connected();
        let eng = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Engineering" })), &admin);
        for mapping in [
            json!({ "channel": "C0SAMECHAN" }),
            json!({ "channel": "C0SAMECHAN", "topic_id": eng["id"], "updated_posts": true }),
            json!({ "channel": "C0OTHERCHAN", "topic_id": eng["id"] }),
        ] {
            h.ok("POST", "/api/v1/slack/channels", Some(mapping), &admin);
        }
        // A channel has one ID but many names over time: only IDs are taken, so a name can't
        // become a second queue for a channel that's already mapped by its ID.
        for name in ["#announcements", "announcements", "c0samechan", "#C0SAMECHAN", "C0SAME CHAN", "D0DIRECTMSG", "C0SHORT"] {
            let r = h.call("POST", "/api/v1/slack/channels", Some(json!({ "channel": name })), &admin);
            assert_eq!(r.status, 400, "{name}");
            assert!(r.body["error"]["message"].as_str().unwrap().contains("copy the Channel ID"), "{name}: {}", r.body);
        }
        let mapped = h.ok("GET", "/api/v1/slack", None, &admin)["channels"].clone();
        let first = mapped[0]["id"].as_str().unwrap();
        let renamed = h.call("PATCH", &format!("/api/v1/slack/channels/{first}"), Some(json!({ "channel": "#announcements" })), &admin);
        assert_eq!(renamed.status, 400);
        assert_eq!(h.ok("GET", "/api/v1/slack", None, &admin)["channels"], mapped, "nothing changed");
        let to =
            |r: &Res| -> Vec<String> { slack_messages(&r.effects).iter().map(|m| m["channel"].as_str().unwrap().to_string()).collect() };

        // A post both of a channel's mappings match: one message there.
        let r = h.call("POST", "/api/v1/posts", Some(json!({ "title": "Once", "status": "published", "topic_ids": [eng["id"]] })), &admin);
        assert_eq!(to(&r), vec!["C0SAMECHAN", "C0OTHERCHAN"]);
        let queues: Vec<&str> = r
            .effects
            .iter()
            .filter_map(|e| match e {
                Effect::Webhook(d) => Some(d.webhook_id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(queues, vec!["slack:C0SAMECHAN", "slack:C0OTHERCHAN"], "one delivery queue per channel");

        // Four posts in one request, two mappings to one channel: three messages there, each about
        // a different post.
        let docs: Vec<Value> = (0..4).map(|i| json!({ "title": format!("Runbook {i}"), "content": "x", "topic": "Engineering" })).collect();
        let r = h.call("POST", "/api/v1/import", Some(json!({ "documents": docs })), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let messages = slack_messages(&r.effects);
        for channel in ["C0SAMECHAN", "C0OTHERCHAN"] {
            let mut posts: Vec<String> =
                messages.iter().filter(|m| m["channel"] == channel).map(|m| m["text"].as_str().unwrap().to_string()).collect();
            assert_eq!(posts.len(), 3, "{channel}: {posts:?}");
            posts.dedup();
            assert_eq!(posts.len(), 3, "{channel} heard about a post twice: {posts:?}");
        }
    }

    /// A command Slack was told about must not vanish: when a step fails and rolls back, the host
    /// sends the job's failure notice to the response_url, without internals.
    #[test]
    fn slack_failed_drafts_still_get_an_answer() {
        let (h, admin) = connected();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let post = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Shared", "status": "published" })), &admin);
        let form = "application/x-www-form-urlencoded";
        // A host's step: the step and its own check in one transaction, rolled back on failure,
        // and the notice to send then (the native server has no check of its own).
        let one_step = |job: &mut Job, replies: Vec<HttpReply>, refuse: Option<dumbslab_core::ApiError>| {
            h.store
                .with_tx(|db| {
                    let (step, notice) = connect::guarded_step(db, &h.cfg, job, replies, chrono::Utc::now(), |_| refuse);
                    let ok = step.is_ok();
                    ((step, notice), ok)
                })
                .unwrap()
        };
        let r = h.send(&signed_at("/slack/commands", &command_body("UMO", "new Rollback me"), form, now(), SECRET));
        let mut job = later_of(&r).unwrap();
        let (Ok(Step::Fetch(calls)), None) = one_step(&mut job, vec![], None) else { panic!("asks who's asking") };

        // Creating the post fails part-way (a database error): the step rolls back...
        db_run(&h, |db| db.execute_batch("DROP TABLE post_versions"));
        let posts = count(&h, "SELECT COUNT(*) FROM posts");
        let (step, notice) = one_step(&mut job, calls.iter().map(slack_api).collect(), None);
        let failed = step.expect_err("the step fails");
        assert_eq!(failed.status, 500, "{failed:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM posts"), posts, "nothing was kept");
        // ...and the person hears so at the response_url, with nothing about why inside.
        let notice = notice.expect("a notice");
        assert_eq!((notice.method, notice.url.as_str()), ("POST", REPLY_TO));
        assert!(!notice.headers.iter().any(|(k, _)| k == "authorization"));
        let body: Value = serde_json::from_str(notice.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["response_type"], "ephemeral");
        let text = text_of(&body);
        assert!(text.contains("Couldn't create the draft: something went wrong"), "{text}");
        for internal in ["post_versions", "database", "table", &failed.message] {
            assert!(!text.contains(internal), "{internal} in {text}");
        }
        // The Worker refuses a step that grows a full workspace; that message is for people.
        let full = dumbslab_core::plan::storage_full(&plans(None), dumbslab_core::plan::Plan::Free, false);
        let text = text_of(&serde_json::from_str::<Value>(job.failure_notice(&full).unwrap().body.as_deref().unwrap()).unwrap());
        assert!(text.contains("Couldn't create the draft. This workspace has reached its 50 MB storage limit"), "{text}");

        // A search says so too; once an answer went, or for a preview, there's nothing to send.
        let r = h.send(&signed_at("/slack/commands", &command_body("UMO", "search anything"), form, now(), SECRET));
        let mut search = later_of(&r).unwrap();
        assert!(
            text_of(&serde_json::from_str::<Value>(search.failure_notice(&failed).unwrap().body.as_deref().unwrap()).unwrap())
                .contains("Couldn't search DumbSlab")
        );
        let (Ok(Step::Fetch(calls)), _) = one_step(&mut search, vec![], None) else { panic!() };
        let (Ok(Step::Fetch(answer)), _) = one_step(&mut search, calls.iter().map(slack_api).collect(), None) else { panic!() };
        assert_eq!(answer[0].url, REPLY_TO);
        // The host sent that answer before the next step, so a failure there sends nothing more.
        let (step, notice) = one_step(&mut search, vec![HttpReply { status: 200, body: "ok".into() }], Some(failed.clone()));
        assert!(step.is_err() && notice.is_none(), "answered already");
        let r = h.send(&signed_at(
            "/slack/events",
            &event(&[post["url"].as_str().unwrap()], "UMO", "composer"),
            "application/json",
            now(),
            SECRET,
        ));
        assert!(later_of(&r).unwrap().failure_notice(&failed).is_none());
    }

    /// The Worker checks a step's storage after the step ran. A `/dumbslab new` step that made the
    /// draft and prepared its answer, then grew a full workspace, is rolled back whole: no draft,
    /// and the answer never goes. So the notice is decided from the job as it was before the step,
    /// and the person hears exactly once.
    #[test]
    fn slack_drafts_refused_after_the_step_still_get_one_answer() {
        use dumbslab_core::plan;
        let (mut h, admin) = hosted(None);
        h.cfg.connectors.key = Some("connector-key".into());
        let r = h.call("PATCH", "/api/v1/slack", Some(json!({ "bot_token": TOKEN, "signing_secret": SECRET })), &admin);
        assert!(matches!(drive(&h, job_of(&r).unwrap()).0, Finish::Fill(_)));
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let full = plan::storage_full(&plans(None), plan::Plan::Free, false);

        // The host's loop, with the Worker's storage guard refusing the second step.
        let r =
            h.send(&signed_at("/slack/commands", &command_body("UMO", "new Too big"), "application/x-www-form-urlencoded", now(), SECRET));
        let mut job = later_of(&r).unwrap();
        let (mut replies, mut sent, mut notices) = (vec![], vec![], vec![]);
        for refuse in [None, Some(full.clone())] {
            let (step, notice) = h
                .store
                .with_tx(|db| {
                    let (step, notice) = connect::guarded_step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now(), |_| refuse);
                    let ok = step.is_ok();
                    ((step, notice), ok)
                })
                .unwrap();
            notices.extend(notice);
            match step {
                Ok(Step::Fetch(calls)) => {
                    replies = calls.iter().map(slack_api).collect();
                    sent.extend(calls);
                }
                Err(e) => {
                    assert_eq!(e.code, "storage_full");
                    break;
                }
                Ok(other) => panic!("{other:?}"),
            }
        }
        // The core step had made the draft and prepared its answer before the guard refused it:
        // asked afterwards, the job would say it had answered already.
        assert!(job.failure_notice(&full).is_none());
        // But the rollback kept nothing, the prepared answer never went, and one notice did.
        assert_eq!(count(&h, "SELECT COUNT(*) FROM posts WHERE title = 'Too big'"), 0, "no draft remains");
        assert!(sent.iter().all(|c| c.url != REPLY_TO), "{sent:?}");
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert_eq!((notices[0].method, notices[0].url.as_str()), ("POST", REPLY_TO));
        let text = text_of(&serde_json::from_str::<Value>(notices[0].body.as_deref().unwrap()).unwrap());
        assert!(text.contains("Couldn't create the draft. This workspace has reached its 50 MB storage limit"), "{text}");
    }

    /// Hosts record each job step's writes as soon as its transaction ends (the Worker's
    /// `drive_job`), so a step that runs while other jobs wait on Slack is metered against them.
    /// Here two overlapping commands each start a draft on a hosted workspace with room for one
    /// more change: the first uses it up while the second waits on users.info, and the second is
    /// refused at its next step, with the reason posted to its response_url.
    #[test]
    fn slack_job_steps_are_metered_as_they_go() {
        use dumbslab_core::plan;
        let (mut h, admin) = hosted(None);
        h.cfg.connectors.key = Some("connector-key".into());
        let r = h.call("PATCH", "/api/v1/slack", Some(json!({ "bot_token": TOKEN, "signing_secret": SECRET })), &admin);
        assert!(matches!(drive(&h, job_of(&r).unwrap()).0, Finish::Fill(_)));
        h.user(&admin, "mo@acme.test", "Mo", "member");
        let form = "application/x-www-form-urlencoded";
        let one_step = |job: &mut Job, replies: Vec<HttpReply>| -> Vec<HttpCall> {
            let step = h
                .store
                .with_tx(|db| {
                    let step = connect::step(db, &h.cfg, job, replies, chrono::Utc::now());
                    let ok = step.is_ok();
                    (step, ok)
                })
                .unwrap();
            match step.unwrap() {
                Step::Fetch(calls) => calls,
                other => panic!("{other:?}"),
            }
        };
        // What the host does once a step's transaction ends: count its rows right away.
        let meter = |rows: u64| db_run(&h, |db| plan::record_writes(db, chrono::Utc::now(), rows));
        let limit = plans(None).free.writes_per_day;

        let first = h.send(&signed_at("/slack/commands", &command_body("UMO", "new First"), form, now(), SECRET));
        let second = h.send(&signed_at("/slack/commands", &command_body("UMO", "new Second"), form, now(), SECRET));
        let (mut a, mut b) = (later_of(&first).unwrap(), later_of(&second).unwrap());
        // Both wait on users.info. One change's worth of the allowance is left.
        let (asks_a, asks_b) = (one_step(&mut a, vec![]), one_step(&mut b, vec![]));
        let used = db_run(&h, |db| plan::writes_24h(db, chrono::Utc::now()));
        meter(limit - 1 - used);

        // The first creates its draft, and its rows are counted as soon as its step ends, before
        // it waits on the response_url.
        let answer_a = one_step(&mut a, asks_a.iter().map(slack_api).collect());
        assert!(text_of(&posted_answer(&answer_a)).contains("Started a draft"));
        meter(20);
        // So the second, which was waiting meanwhile, is refused, and hears why.
        let answer_b = posted_answer(&one_step(&mut b, asks_b.iter().map(slack_api).collect()));
        assert!(text_of(&answer_b).contains("changes are paused"), "{answer_b}");
        let titles = db_run(&h, |db| db.query("SELECT title FROM posts WHERE title IN ('First', 'Second')", &[]));
        assert_eq!(titles.iter().map(|r| r.str("title")).collect::<Vec<_>>(), vec!["First"]);
    }

    #[test]
    fn slack_secrets_are_never_returned() {
        let (h, admin) = connected();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let leaks = |what: &str, text: &str| {
            assert!(!text.contains(TOKEN) && !text.contains(SECRET), "{what} shows a secret: {text}");
        };
        let settings = h.ok("GET", "/api/v1/slack", None, &admin);
        leaks("get_slack", &settings.to_string());
        assert_eq!((settings["bot_token_saved"].as_bool(), settings["signing_secret_saved"].as_bool()), (Some(true), Some(true)));
        assert_eq!(settings["manifest"]["features"]["slash_commands"][0]["url"], "https://kb.test/slack/commands");
        assert_eq!(settings["manifest"]["features"]["unfurl_domains"], json!(["kb.test"]));
        leaks("update_slack", &h.ok("PATCH", "/api/v1/slack", Some(json!({ "unfurls": true })), &admin).to_string());
        leaks("export", &h.ok("GET", "/api/v1/export", None, &admin).to_string());
        leaks("activity", &h.ok("GET", "/api/v1/activity", None, &admin).to_string());
        let mcp = h.mcp(
            &admin,
            "",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "get_slack", "arguments": {} } }),
        );
        leaks("MCP", &mcp.body.to_string());
        // Stored encrypted.
        let stored = db_run(&h, |db| db.one("SELECT bot_token, signing_secret FROM slack_app", &[])).unwrap();
        leaks("the database", &format!("{} {}", stored.str("bot_token"), stored.str("signing_secret")));
        // Only admins see Slack's settings.
        assert_eq!(h.call("GET", "/api/v1/slack", None, &mo).status, 403);
        assert_eq!(h.call("PATCH", "/api/v1/slack", Some(json!({ "unfurls": false })), &mo).status, 403);

        // A token Slack refuses, or that isn't a bot token, changes nothing.
        assert_eq!(h.call("PATCH", "/api/v1/slack", Some(json!({ "bot_token": "xoxp-user-token" })), &admin).status, 400);
        assert_eq!(h.call("PATCH", "/api/v1/slack", Some(json!({ "signing_secret": "short" })), &admin).status, 400);
        let r = h.call("PATCH", "/api/v1/slack", Some(json!({ "bot_token": "xoxb-revoked" })), &admin);
        let mut job = job_of(&r).unwrap();
        let checked = h.store.with_tx(|db| {
            let s = connect::step(db, &h.cfg, &mut job, vec![], chrono::Utc::now());
            (s, true)
        });
        assert!(matches!(checked, Ok(Ok(Step::Fetch(_)))));
        let refused = HttpReply { status: 200, body: json!({ "ok": false, "error": "invalid_auth" }).to_string() };
        let done = h.store.with_tx(|db| (connect::step(db, &h.cfg, &mut job, vec![refused], chrono::Utc::now()), true)).unwrap().unwrap();
        assert!(matches!(done, Step::Done(Finish::Fail(ref e)) if e.message.contains("didn't accept that bot token")), "{done:?}");
        // The working token stays.
        let r = h.send(&signed_at("/slack/commands", &command_body("UMO", "search x"), "application/x-www-form-urlencoded", now(), SECRET));
        assert!(later_of(&r).is_some());

        // Without the connector key, secrets can't be kept.
        let mut h = h;
        h.cfg.connectors.key = None;
        assert_eq!(h.call("PATCH", "/api/v1/slack", Some(json!({ "signing_secret": SECRET })), &admin).status, 503);
        let settings = h.ok("GET", "/api/v1/slack", None, &admin);
        assert_eq!((settings["available"].as_bool(), settings["connected"].as_bool()), (Some(false), Some(false)));
        // And nothing can be verified: Slack's requests are refused.
        let r = h.send(&signed_at("/slack/commands", &command_body("UMO", "search x"), "application/x-www-form-urlencoded", now(), SECRET));
        assert_eq!(r.status, 404);
    }
}

#[test]
fn healthz_reports_build_identity_without_auth() {
    let h = H::new();
    let r = h.call("GET", "/healthz", None, &Auth::None);
    assert_eq!(r.status, 200);
    assert_eq!(
        r.body,
        json!({
            "ok": true,
            "version": dumbslab_core::VERSION,
            "git_sha": dumbslab_core::GIT_SHA,
        })
    );
    let sha = dumbslab_core::GIT_SHA;
    assert!(sha == "unknown" || ((sha.len() == 40 || sha.len() == 64) && sha.bytes().all(|b| b.is_ascii_hexdigit())));
}

// ---------------------------------------------------------------------------
// People sync (BambooHR) and docs sync (GitHub, GitLab). The tests play the host and the apps:
// they run each sync's steps with canned answers.

mod syncs {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use dumbslab_core::connect::{self, Finish, HttpCall, HttpReply, Job, Step};
    use dumbslab_core::util::hmac_sha256_hex;

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
            .unwrap_or_else(|| panic!("a sync job; got {} {}", r.status, r.body))
    }

    /// Runs a job like a host: at most MAX_STEPS steps, each in its own transaction.
    fn drive(h: &H, job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Finish, Vec<HttpCall>) {
        let (finish, sent, _) = drive_all(h, job, answer);
        (finish, sent)
    }

    /// Like [`drive`], with the effects the job left for the host.
    fn drive_all(h: &H, mut job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Finish, Vec<HttpCall>, Vec<Effect>) {
        let mut replies = vec![];
        let mut sent = vec![];
        for _ in 0..connect::MAX_STEPS {
            let (step, next) = h
                .store
                .with_tx(|db| {
                    let (step, _) = connect::guarded_step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now(), |_| None);
                    let ok = step.is_ok();
                    ((step, job.clone()), ok)
                })
                .unwrap();
            job = next;
            match step.unwrap() {
                Step::Done(f) => return (f, sent, job.take_effects()),
                Step::Fetch(calls) => {
                    replies = calls.iter().map(answer).collect();
                    sent.extend(calls);
                }
            }
        }
        panic!("the sync took more steps than a host allows");
    }

    fn filled(finish: Finish) -> Value {
        match finish {
            Finish::Fill(v) => v,
            other => panic!("expected a result, got {other:?}"),
        }
    }

    fn ok(body: Value) -> HttpReply {
        HttpReply { status: 200, body: body.to_string() }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A webhook delivery, with the headers the sender adds.
    fn hook(h: &H, path: &str, body: &str, headers: &[(&str, &str)]) -> Res {
        let mut all = vec![("content-type".to_string(), "application/json".to_string())];
        all.extend(headers.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        h.send(&Request {
            method: "POST".into(),
            path: path.into(),
            query: String::new(),
            headers: all,
            body: body.as_bytes().to_vec(),
            origin: "https://kb.test".into(),
            client_ip: None,
        })
    }

    fn details(h: &H, admin: &Auth, user: &str) -> Value {
        h.ok("GET", &format!("/api/v1/users/{}", urlencoding::encode(user)), None, admin)["details"].clone()
    }

    // -----------------------------------------------------------------------
    // People

    fn employee(id: &str, name: &str, email: &str, title: &str, department: &str, manager: Option<&str>) -> Value {
        json!({ "employeeId": id, "displayName": name, "workEmail": email, "jobTitleName": title, "departmentName": department,
                "locationName": "Portland", "workPhone": "555-0100", "pronouns": "they/them", "reportsToId": manager, "_restrictedFields": [] })
    }

    fn bamboo(pages: Vec<Value>) -> impl Fn(&HttpCall) -> HttpReply {
        move |call: &HttpCall| {
            let page = if call.url.contains("page%5Bafter%5D=c2") { 1 } else { 0 };
            let next = if page + 1 < pages.len() { json!("c2") } else { Value::Null };
            ok(json!({ "data": pages[page], "meta": { "total": 0, "page": { "limit": 2500, "nextCursor": next } } }))
        }
    }

    /// Saves the people sync like an admin in Settings: the host checks the key with BambooHR and
    /// adds its webhook, answered by `answer`. Returns the answer and the requests sent.
    fn save_people(h: &H, auth: &Auth, body: Value, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Value, Vec<HttpCall>) {
        let r = h.call("PUT", "/api/v1/people-sync", Some(body), auth);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(h, job_of(&r), answer);
        (filled(finish), sent)
    }

    fn basic(key: &str) -> (String, String) {
        ("authorization".into(), format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{key}:x"))))
    }

    /// A fake BambooHR: no employees, the fields webhooks may watch, webhooks added with ids
    /// counting up from `next` and private keys `pk-<id>`, and OAuth tokens `at-<n>` / `rt-<n>`.
    /// `refuse` answers instead, by kind of request: `token`, `check`, `fields`, `list`, `get`,
    /// `add` or `delete` (status 0 is a timeout).
    struct FakeBamboo {
        next: std::cell::Cell<u32>,
        tokens: std::cell::Cell<u32>,
        /// The webhooks it has, by id: its company, where it posts, and its name.
        hooks: RefCell<BTreeMap<String, (String, String, String)>>,
        refuse: RefCell<BTreeMap<&'static str, HttpReply>>,
    }

    impl FakeBamboo {
        fn new(next: u32) -> FakeBamboo {
            FakeBamboo {
                next: std::cell::Cell::new(next),
                tokens: std::cell::Cell::new(0),
                hooks: RefCell::new(BTreeMap::new()),
                refuse: RefCell::new(BTreeMap::new()),
            }
        }

        fn refuse(&self, kind: &'static str, status: u16, body: Value) {
            self.refuse.borrow_mut().insert(kind, HttpReply { status, body: body.to_string() });
        }

        fn ids(&self) -> Vec<String> {
            self.hooks.borrow().keys().cloned().collect()
        }

        fn answer(&self, call: &HttpCall) -> HttpReply {
            let url = call.url.split('?').next().unwrap_or_default();
            let kind = match (call.method, url) {
                ("POST", u) if u.ends_with("/token.php") => "token",
                ("GET", u) if u.ends_with("/api/v1/employees") => "check",
                ("GET", u) if u.ends_with("/api/v1/webhooks/monitor_fields") => "fields",
                ("GET", u) if u.ends_with("/api/v1/webhooks") => "list",
                ("GET", u) if u.contains("/api/v1/webhooks/") => "get",
                ("POST", u) if u.ends_with("/api/v1/webhooks") => "add",
                ("DELETE", _) => "delete",
                other => panic!("unexpected request {other:?}"),
            };
            let id = url.rsplit('/').next().unwrap_or_default().to_string();
            // Each company sees only its own webhooks.
            let company = url.trim_start_matches("https://").split('.').next().unwrap_or_default().to_string();
            let theirs = |c: &str| c == company;
            if let Some(r) = self.refuse.borrow().get(kind) {
                return r.clone();
            }
            match kind {
                "check" => ok(json!({ "data": [], "meta": { "total": 0, "page": { "limit": 1, "nextCursor": null } } })),
                "fields" => ok(json!({ "fields": [
                    { "id": "4175", "name": "Accrual Level Start Date", "alias": null },
                    { "id": "15", "name": "Work Email", "alias": "workEmail" },
                    { "id": "17", "name": "Job Title", "alias": "jobTitle" },
                    { "id": "4", "name": "Department", "alias": "department" },
                    { "id": "18", "name": "Location", "alias": "location" },
                    { "id": "16", "name": "Work Phone", "alias": "workPhone" },
                    { "id": "91", "name": "Reporting To", "alias": "reportsTo" },
                    { "id": "4400", "name": "Pronouns", "alias": null },
                    { "id": "1", "name": "First Name", "alias": "firstName" }
                ] })),
                "token" => {
                    let n = self.tokens.get() + 1;
                    self.tokens.set(n);
                    let company = url.trim_start_matches("https://").split('.').next().unwrap_or_default();
                    ok(json!({ "access_token": format!("at-{n}"), "refresh_token": format!("rt-{n}"), "expires_in": 3600,
                               "token_type": "Bearer", "scope": "openid offline_access employee webhooks webhooks.write",
                               "id_token": "x.y.z", "companyDomain": company }))
                }
                "list" => {
                    ok(json!({ "webhooks": self.hooks.borrow().iter().filter(|(_, (c, _, _))| theirs(c)).map(|(id, (_, url, name))| json!({
                    "id": id, "name": name, "created": "2026-10-31 18:00:00", "lastSent": null, "url": url })).collect::<Vec<_>>() }))
                }
                "get" => match self.hooks.borrow().get(&id).filter(|(c, _, _)| theirs(c)) {
                    Some((_, posts_to, name)) => {
                        ok(json!({ "id": id, "name": name, "url": posts_to, "format": "json", "events": ["employee.updated"] }))
                    }
                    None => HttpReply {
                        status: 404,
                        body: json!({ "errors": [{ "error": format!("No webhook was found with ID: {id}.") }] }).to_string(),
                    },
                },
                "add" => {
                    let id = self.next.get();
                    self.next.set(id + 1);
                    let body: Value = serde_json::from_str(call.body.as_deref().unwrap_or_default()).unwrap();
                    let (url, name) = (body["url"].as_str().unwrap_or_default(), body["name"].as_str().unwrap_or_default());
                    self.hooks.borrow_mut().insert(id.to_string(), (company.clone(), url.to_string(), name.to_string()));
                    HttpReply {
                        status: 201,
                        body: json!({ "id": id.to_string(), "name": body["name"], "created": "2026-10-31 18:00:00", "lastSent": null,
                                      "monitorFields": body["monitorFields"], "postFields": {}, "url": body["url"], "format": "json",
                                      "privateKey": format!("pk-{id}") })
                        .to_string(),
                    }
                }
                _ if self.hooks.borrow().get(&id).is_some_and(|(c, _, _)| theirs(c)) => {
                    self.hooks.borrow_mut().remove(&id);
                    HttpReply { status: 200, body: "Web hook has been deleted.".into() }
                }
                _ => HttpReply { status: 404, body: "{}".into() },
            }
        }
    }

    /// A BambooHR webhook delivery signed with `key`.
    fn people_hook(h: &H, key: &str) -> Res {
        let at = chrono::Utc::now().timestamp().to_string();
        let body = json!({ "type": "employee.updated", "timestamp": "2026-10-31T18:00:00+0000",
                           "data": { "companyId": "1", "employeeId": dumbslab_core::util::new_id(), "changedFields": ["jobTitle"] } })
        .to_string();
        let sig = hmac_sha256_hex(key, &format!("{body}{at}"));
        hook(h, "/hooks/people", &body, &[("x-bamboohr-timestamp", &at), ("x-bamboohr-signature", &sig)])
    }

    #[test]
    fn people_sync_fills_profiles_by_work_email() {
        let mut h = H::new();
        let (admin, admin_token) = h.setup();
        let (mo_id, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let (zed_id, _) = h.user(&admin, "Zed@Acme.test", "Zed", "member");
        let (_, _) = h.user(&admin, "gone@acme.test", "Gone", "member");
        h.ok("PATCH", "/api/v1/users/gone@acme.test", Some(json!({ "deactivated": true })), &admin);
        h.ok("POST", "/api/v1/users", Some(json!({ "email": "bot@acme.test", "name": "Bot", "is_bot": true })), &admin);
        let setup = json!({ "subdomain": "acme.bamboohr.com", "api_key": "bamboo-secret-key", "webhook_key": "bamboo-hook-key" });
        let accept = bamboo(vec![json!([])]);

        // Without a connector key there's nothing to encrypt credentials with.
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["enabled"], false);
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(setup.clone()), &admin).status, 503);
        with_key(&mut h);

        // Admins only, and keys are checked.
        assert_eq!(h.call("GET", "/api/v1/people-sync", None, &mo).status, 403);
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(setup.clone()), &mo).status, 403);
        assert_eq!(h.call("POST", "/api/v1/people-sync/run", None, &mo).status, 403);
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme" })), &admin).status, 400, "a key is required");
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "evil.test/x", "api_key": "k" })), &admin).status, 400);
        assert_eq!(h.call("POST", "/api/v1/people-sync/run", None, &admin).status, 404, "not set up yet");

        // A pasted webhook private key: DumbSlab adds no webhook of its own, and only checks the key.
        let (v, sent) = save_people(&h, &admin, setup, &accept);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert!(sent[0].url.starts_with("https://acme.bamboohr.com/api/v1/employees?fields=workEmail&"), "{}", sent[0].url);
        assert_eq!((v["subdomain"].as_str(), v["webhook"].as_bool()), (Some("acme"), Some(true)));
        assert_eq!((v["automatic_webhook"].as_bool(), &v["webhook_error"]), (Some(false), &Value::Null));
        assert_eq!(v["webhook_url"], "https://kb.test/hooks/people");
        // Credentials are encrypted and never come back.
        let stored =
            count(&h, "SELECT COUNT(*) FROM people_sync WHERE secret LIKE '%bamboo-secret-key%' OR secret LIKE '%bamboo-hook-key%'");
        assert_eq!(stored, 0);
        for r in [h.ok("GET", "/api/v1/people-sync", None, &admin), h.ok("GET", "/api/v1/activity", None, &admin)] {
            assert!(!r.to_string().contains("bamboo-secret-key") && !r.to_string().contains("bamboo-hook-key"), "{r}");
        }
        // Leaving the keys out keeps them.
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &accept);
        assert_eq!((v["webhook"].as_bool(), v["automatic_webhook"].as_bool()), (Some(true), Some(false)));

        let ada_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        let mut zed = employee("3", "Zed Z", "zed@acme.test", "Designer", "", Some("1"));
        zed["_restrictedFields"] = json!(["departmentName"]);
        zed["departmentName"] = Value::Null;
        let earlier =
            "INSERT INTO user_profiles (user_id, department, updated_at) SELECT id, 'Brand', '' FROM users WHERE email = 'Zed@Acme.test'";
        db_run(&h, |db| db.execute(earlier, &[]));
        let page1 = json!([
            employee("1", "Ada Admin", "ADA@acme.test", "CEO", "Leadership", None),
            employee("2", "Mo M", "Mo@ACME.test", "Engineer", "Platform", Some("1")),
            zed,
        ]);
        let page2 = json!([
            employee("4", "Nobody", "nobody@acme.test", "Analyst", "Finance", None),
            employee("5", "No Email", "", "Temp", "", None),
            employee("6", "Bot", "bot@acme.test", "Robot", "", None),
            employee("7", "Gone", "gone@acme.test", "Former", "", None),
            employee("8", "Mo Again", "mo@acme.test", "Duplicate", "", None),
        ]);
        let answer = bamboo(vec![page1, page2]);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        let v = filled(finish);
        assert_eq!(sent.len(), 2, "two pages");
        assert!(sent[0].url.starts_with("https://acme.bamboohr.com/api/v1/employees?fields="), "{}", sent[0].url);
        assert!(sent[0].url.contains("filter%5Bstatus%5D=active"));
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("bamboo-secret-key:x"));
        assert!(sent.iter().all(|c| c.headers.contains(&("authorization".into(), basic.clone()))));
        assert_eq!((v["employees"].as_i64(), v["matched"].as_i64(), v["updated"].as_i64()), (Some(8), Some(3), Some(3)), "{v}");
        assert_eq!(v["skipped"], 4, "no email, a bot, a deactivated account and a repeated email: {v}");
        assert_eq!(v["not_found"], json!([{ "name": "Nobody", "email": "nobody@acme.test" }]));
        assert_eq!(v["truncated"], false);

        // Matched case-insensitively; the manager links when they're here too.
        let mo_user = details(&h, &admin, "mo@acme.test");
        assert_eq!(
            (mo_user["title"].as_str(), mo_user["department"].as_str(), mo_user["location"].as_str(), mo_user["pronouns"].as_str()),
            (Some("Engineer"), Some("Platform"), Some("Portland"), Some("they/them"))
        );
        let profile = h.ok("GET", &format!("/api/v1/users/{mo_id}"), None, &mo);
        assert_eq!(profile["manager"]["id"].as_str(), Some(ada_id.as_str()), "everyone sees the manager");
        // A field the key may not read is left as it was.
        let zed_user = details(&h, &admin, &zed_id);
        assert_eq!((zed_user["title"].as_str(), zed_user["department"].as_str()), (Some("Designer"), Some("Brand")));
        // Nobody is added, and the bot and the deactivated account are untouched.
        assert_eq!(count(&h, "SELECT COUNT(*) FROM users WHERE email = 'nobody@acme.test'"), 0);
        let untouched =
            "SELECT COUNT(*) FROM user_profiles p JOIN users u ON u.id = p.user_id WHERE u.is_bot = 1 OR u.deactivated_at IS NOT NULL";
        assert_eq!(count(&h, untouched), 0);
        let state = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((state["last_status"].as_str(), state["running"].as_bool()), (Some("ok"), Some(false)));
        assert_eq!(state["last_result"]["updated"], 3);

        // Again: nothing changes.
        let r = h.call("POST", "/api/v1/people-sync/run", Some(json!({})), &admin_token);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((v["updated"].as_i64(), v["unchanged"].as_i64()), (Some(0), Some(3)));

        // One sync at a time.
        let first = job_of(&h.call("POST", "/api/v1/people-sync/run", None, &admin));
        assert_eq!(h.call("POST", "/api/v1/people-sync/run", None, &admin).status, 409);

        // Webhooks: signed with the private key over the body and the timestamp, which must be
        // within 5 minutes of now. Each delivery works once.
        let now = chrono::Utc::now().timestamp();
        let deliver = |change: &str, at: i64| -> Res {
            let body = json!({ "type": "employee.updated", "data": { "employeeId": change } }).to_string();
            let at = at.to_string();
            let sig = hmac_sha256_hex("bamboo-hook-key", &format!("{body}{at}"));
            hook(&h, "/hooks/people", &body, &[("x-bamboohr-timestamp", &at), ("x-bamboohr-signature", &sig)])
        };
        let body = json!({ "type": "employee.updated" }).to_string();
        let at = now.to_string();
        assert_eq!(hook(&h, "/hooks/people", &body, &[("x-bamboohr-timestamp", &at), ("x-bamboohr-signature", "00")]).status, 401);
        let sig = hmac_sha256_hex("bamboo-hook-key", &format!("{body}{at}"));
        let tampered = format!("{body} ");
        assert_eq!(
            hook(&h, "/hooks/people", &tampered, &[("x-bamboohr-timestamp", &at), ("x-bamboohr-signature", &sig)]).status,
            401,
            "the body is signed"
        );
        assert_eq!(deliver("stale", now - 6 * 60).status, 401, "too old");
        assert_eq!(deliver("future", now + 6 * 60).status, 401, "from the future");
        let garbled = hmac_sha256_hex("bamboo-hook-key", &format!("{body}soon"));
        assert_eq!(hook(&h, "/hooks/people", &body, &[("x-bamboohr-timestamp", "soon"), ("x-bamboohr-signature", &garbled)]).status, 401);
        // While a sync runs, a webhook is noted, and Settings says to sync again.
        let r = deliver("2", now);
        assert_eq!((r.status, r.body["status"].as_str()), (200, Some("queued")), "{}", r.body);
        assert!(r.effects.is_empty());
        assert_eq!(deliver("2", now).status, 409, "a replay of the same delivery is refused");
        drive(&h, first, &answer);
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["pending"], true);
        let r = deliver("3", now - 60);
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["pending"], false);
        assert_eq!(deliver("3", now - 60).status, 409, "replayed after it ran");

        // BambooHR refusing the key fails the sync and says why.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_| HttpReply { status: 401, body: String::new() });
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("rejected the API key")), "{finish:?}");
        let state = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!(state["last_status"], "failed");
        assert_eq!(state["last_result"]["updated"], 0, "the last good result stays");

        // Without a webhook key (here BambooHR won't let DumbSlab add one), its address is gone;
        // removing the sync keeps the profiles.
        let no_webhooks = |c: &HttpCall| if c.url.contains("/webhooks") { HttpReply { status: 403, body: "{}".into() } } else { accept(c) };
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme", "webhook_key": "" }), &no_webhooks);
        assert_eq!((v["webhook"].as_bool(), v["webhook_error"].is_string()), (Some(false), true), "{v}");
        assert_eq!(deliver("4", now).status, 404);
        h.ok("DELETE", "/api/v1/people-sync", None, &admin);
        assert_eq!(details(&h, &admin, "mo@acme.test")["title"], "Engineer");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync"), 0);
    }

    #[test]
    fn people_sync_adds_its_own_bamboohr_webhook() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        with_key(&mut h);
        let fake = FakeBamboo::new(41);
        let answer = |c: &HttpCall| fake.answer(c);
        let urls = |sent: &[HttpCall]| -> Vec<(String, String)> {
            sent.iter().map(|c| (c.method.to_string(), c.url.split('?').next().unwrap().to_string())).collect()
        };
        let webhooks = "https://acme.bamboohr.com/api/v1/webhooks";
        let call = |m: &str, u: &str| (m.to_string(), u.to_string());

        // One step: the company domain as it was pasted, and the API key. DumbSlab checks the key,
        // then adds the webhook in BambooHR.
        let body = json!({ "subdomain": "https://Acme.bamboohr.com/home?tab=1", "api_key": "key-1" });
        let (v, sent) = save_people(&h, &admin, body, &answer);
        assert_eq!(
            urls(&sent),
            [
                call("GET", "https://acme.bamboohr.com/api/v1/employees"),
                call("GET", "https://acme.bamboohr.com/api/v1/webhooks/monitor_fields"),
                call("POST", webhooks)
            ]
        );
        assert!(sent[0].url.contains("page%5Blimit%5D=1"), "a cheap check: {}", sent[0].url);
        assert!(sent.iter().all(|c| c.headers.contains(&basic("key-1"))));
        let added: Value = serde_json::from_str(sent[2].body.as_deref().unwrap()).unwrap();
        assert_eq!(added["url"], "https://kb.test/hooks/people");
        assert_eq!((added["format"].as_str(), &added["events"]), (Some("json"), &json!(["employee.updated"])));
        assert_eq!(added["monitorFields"], json!(["workEmail", "jobTitle", "department", "location", "workPhone", "reportsTo", "4400"]));
        assert_eq!(
            (v["subdomain"].as_str(), v["webhook"].as_bool(), v["automatic_webhook"].as_bool()),
            (Some("acme"), Some(true), Some(true))
        );
        assert_eq!((&v["webhook_error"], v.get("notice")), (&Value::Null, None), "{v}");

        // The keys are encrypted and never shown, nor is the webhook's id.
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync WHERE secret LIKE '%key-1%' OR secret LIKE '%pk-41%'"), 0);
        for r in [h.ok("GET", "/api/v1/people-sync", None, &admin), h.ok("GET", "/api/v1/activity", None, &admin)] {
            let text = r.to_string();
            assert!(!text.contains("key-1") && !text.contains("pk-41") && !text.contains("webhook_id"), "{r}");
        }
        let event = &h.ok("GET", "/api/v1/activity", None, &admin)["items"][0];
        assert_eq!((event["event"].as_str(), &event["data"]["automatic_webhook"]), (Some("people_sync.updated"), &json!(true)), "{event}");

        // BambooHR's calls, signed with the webhook's private key, start a sync.
        let r = people_hook(&h, "pk-41");
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // Admins only.
        assert_eq!(h.call("GET", "/api/v1/people-sync", None, &mo).status, 403);
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "k" })), &mo).status, 403);
        assert_eq!(h.call("DELETE", "/api/v1/people-sync", None, &mo).status, 403);

        // A wrong key or company domain is refused before anything changes, here or in BambooHR.
        fake.refuse("check", 401, json!(null));
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "wrong" })), &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        assert!(
            matches!(&finish, Finish::Fail(e) if e.status == 400 && e.message.contains("rejected the API key for acme.bamboohr.com")),
            "{finish:?}"
        );
        assert!(sent.iter().all(|c| c.method == "GET"), "no webhook was added or deleted: {sent:?}");
        fake.refuse("check", 404, json!(null));
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "nope.bamboohr.com" })), &admin);
        let (finish, _) = drive(&h, job_of(&r), &answer);
        assert!(matches!(&finish, Finish::Fail(e) if e.message.contains("no company at nope.bamboohr.com")), "{finish:?}");
        fake.refuse.borrow_mut().clear();
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["subdomain"].as_str(), v["automatic_webhook"].as_bool()), (Some("acme"), Some(true)));
        let r = people_hook(&h, "pk-41");
        assert_eq!(r.status, 200, "the webhook still works: {}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // A new key replaces the webhook: the old one is deleted, with the key that added it and,
        // in case that one was revoked, the new one (the same BambooHR user's, perhaps).
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-2" }), &answer);
        let deletes: Vec<_> = sent.iter().filter(|c| c.method == "DELETE").collect();
        assert_eq!(deletes.len(), 2, "{sent:?}");
        assert!(deletes.iter().all(|c| c.url == format!("{webhooks}/41")));
        assert!(deletes[0].headers.contains(&basic("key-1")) && deletes[1].headers.contains(&basic("key-2")));
        assert!(sent.iter().filter(|c| c.method != "DELETE").all(|c| c.headers.contains(&basic("key-2"))));
        assert_eq!(v["automatic_webhook"], true);
        assert_eq!(people_hook(&h, "pk-41").status, 401, "the old webhook's calls are turned away");
        let r = people_hook(&h, "pk-42");
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // Saving again with nothing changed keeps the webhook, once BambooHR says it still has it.
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!(
            urls(&sent),
            [
                call("GET", "https://acme.bamboohr.com/api/v1/employees"),
                call("GET", "https://acme.bamboohr.com/api/v1/webhooks/monitor_fields"),
                call("GET", &format!("{webhooks}/42"))
            ]
        );
        assert_eq!(v["automatic_webhook"], true);
        let r = people_hook(&h, "pk-42");
        assert_eq!(r.status, 200, "the same webhook, the same key: {}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);
        // Gone from BambooHR (someone deleted it there): saving again adds a new one.
        fake.hooks.borrow_mut().clear();
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert!(sent.iter().any(|c| c.method == "POST"), "{sent:?}");
        assert_eq!(v["automatic_webhook"], true);
        assert_eq!(people_hook(&h, "pk-42").status, 401);
        let r = people_hook(&h, "pk-43");
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // The workspace moved: Settings says to save again, and saving moves the webhook.
        h.cfg.base_url = Some("https://new.test".into());
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!(v["webhook_url"], "https://new.test/hooks/people");
        assert!(v["webhook_error"].as_str().is_some_and(|e| e.contains("address changed")), "{v}");
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!(urls(&sent).iter().filter(|(m, _)| m == "DELETE").count(), 1, "the same key: one try");
        let added: Value = serde_json::from_str(sent.iter().find(|c| c.method == "POST").unwrap().body.as_deref().unwrap()).unwrap();
        assert_eq!(
            (added["url"].as_str(), added["postFields"].clone()),
            (Some("https://new.test/hooks/people"), json!({})),
            "a delivery carries no field values"
        );
        assert!(added["name"].as_str().unwrap().starts_with("DumbSlab people sync (new.test) ds-"), "{added}");
        assert_eq!(v["webhook_error"], Value::Null);
        h.cfg.base_url = Some("https://kb.test".into());

        // BambooHR won't let the key's user add webhooks: the sync is saved anyway, and Settings
        // says why. Syncing on demand still works.
        fake.refuse("fields", 403, json!({ "errors": [{ "error": "You do not have access to webhooks" }] }));
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert!(!sent.iter().any(|c| c.method == "POST"), "{sent:?}");
        assert!(sent.iter().any(|c| c.method == "DELETE" && c.url == format!("{webhooks}/44")), "the old one is deleted: {sent:?}");
        assert_eq!((v["webhook"].as_bool(), v["automatic_webhook"].as_bool()), (Some(false), Some(false)));
        assert!(v["webhook_error"].as_str().is_some_and(|e| e.contains("didn't let DumbSlab add webhooks")), "{v}");
        assert_eq!(people_hook(&h, "pk-44").status, 404, "no webhook, no address");
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        filled(drive(&h, job_of(&r), &answer).0);
        // Or it may not watch some of the fields: BambooHR names them.
        fake.refuse.borrow_mut().clear();
        fake.refuse("add", 403, json!({ "errors": { "monitorFields": [{ "id": 15, "name": "Work Email" }], "unknownFields": [] } }));
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert!(v["webhook_error"].as_str().is_some_and(|e| e.contains("watch these fields") && e.contains("Work Email")), "{v}");
        fake.refuse.borrow_mut().clear();

        // The manual way still works: with a pasted private key, DumbSlab adds no webhook.
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme", "webhook_key": "hand-made" }), &answer);
        assert_eq!(urls(&sent), [call("GET", "https://acme.bamboohr.com/api/v1/employees")]);
        assert_eq!(
            (v["webhook"].as_bool(), v["automatic_webhook"].as_bool(), &v["webhook_error"]),
            (Some(true), Some(false), &Value::Null)
        );
        let r = people_hook(&h, "hand-made");
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);
        // Saving again keeps it; removing it lets DumbSlab add its own again.
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!((sent.len(), v["automatic_webhook"].as_bool()), (1, Some(false)));
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme", "webhook_key": "" }), &answer);
        assert!(sent.iter().any(|c| c.method == "POST"));
        assert_eq!(v["automatic_webhook"], true);
        let id = fake.next.get() - 1;

        // Removing the sync deletes its webhook in BambooHR: a cleanup pass lists the webhooks its
        // key can see, and deletes this workspace's.
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        assert_eq!(filled(finish), json!({ "ok": true }));
        assert!(urls(&sent).contains(&call("GET", webhooks)), "{sent:?}");
        let delete = sent.iter().find(|c| c.method == "DELETE" && c.headers.contains(&basic("key-2"))).unwrap();
        assert_eq!(delete.url, format!("{webhooks}/{id}"));
        assert!(fake.ids().is_empty());
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync"), 0);
        assert_eq!(people_hook(&h, &format!("pk-{id}")).status, 404);

        // When BambooHR won't delete it, the sync is still removed, and the answer says so.
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-3" }), &answer);
        fake.refuse("delete", 500, json!(null));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert!(v["ok"] == true && v["notice"].as_str().is_some_and(|n| n.contains("couldn't delete the webhook")), "{v}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync"), 0);
        assert_eq!(h.call("DELETE", "/api/v1/people-sync", None, &admin).status, 404);
    }

    #[test]
    fn people_sync_webhook_needs_https_and_one_save_at_a_time() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(50);
        let answer = |c: &HttpCall| fake.answer(c);

        // BambooHR calls https addresses only, so on an http one DumbSlab doesn't try.
        h.cfg.base_url = Some("http://localhost:8080".into());
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);
        assert_eq!(sent.len(), 1, "only the key check: {sent:?}");
        assert_eq!((v["configured"].as_bool(), v["webhook"].as_bool()), (Some(true), Some(false)));
        assert!(v["webhook_error"].as_str().is_some_and(|e| e.contains("https") && e.contains("http://localhost:8080")), "{v}");
        h.ok("DELETE", "/api/v1/people-sync", None, &admin);
        h.cfg.base_url = Some("https://kb.test".into());

        // One save at a time: while one is under way, another save, or removing the sync, is
        // refused before anything happens.
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-1" })), &admin);
        let first = job_of(&r);
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-2" })), &admin);
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.effects.is_empty());
        let (finish, _) = drive(&h, first, &answer);
        assert_eq!(filled(finish)["automatic_webhook"], true);
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-2" })), &admin);
        let second = job_of(&r);
        assert_eq!(h.call("DELETE", "/api/v1/people-sync", None, &admin).status, 409);
        let (finish, sent) = drive(&h, second, &answer);
        assert_eq!(filled(finish)["automatic_webhook"], true);
        assert!(sent.iter().any(|c| c.method == "DELETE" && c.url.ends_with("/webhooks/50")), "{sent:?}");
        // A save that fails lets go too.
        fake.refuse("check", 401, json!(null));
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "wrong" })), &admin);
        assert!(matches!(drive(&h, job_of(&r), &answer).0, Finish::Fail(_)));
        fake.refuse.borrow_mut().clear();
        let r = people_hook(&h, "pk-51");
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // BambooHR won't delete the old webhook (its key was revoked, say): the new one is added,
        // and the answer says so.
        fake.refuse("delete", 401, json!(null));
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-3" }), &answer);
        assert_eq!(sent.iter().filter(|c| c.method == "DELETE").count(), 2, "{sent:?}");
        assert_eq!(v["automatic_webhook"], true);
        assert!(v["notice"].as_str().is_some_and(|n| n.contains("couldn't delete the webhook")), "{v}");
        assert!(h.ok("GET", "/api/v1/people-sync", None, &admin).get("notice").is_none(), "only in the answer");
    }

    // -----------------------------------------------------------------------
    // Sign in with BambooHR

    fn with_bamboohr_app(h: &mut H) {
        h.cfg
            .connectors
            .apps
            .insert("bamboohr".into(), connect::OAuthApp { client_id: "bhr-client".into(), client_secret: "bhr-secret".into() });
    }

    /// Starts Sign in with BambooHR; returns BambooHR's link and the state in it.
    fn sign_in_link(h: &H, auth: &Auth, subdomain: &str) -> (String, String) {
        let v = h.ok("POST", "/api/v1/people-sync/sign-in", Some(json!({ "subdomain": subdomain })), auth);
        let url = v["authorize_url"].as_str().unwrap().to_string();
        let state = url.split(['?', '&']).find_map(|p| p.strip_prefix("state=")).unwrap();
        (url.clone(), urlencoding::decode(state).unwrap().into_owned())
    }

    /// BambooHR sends the browser back to the workspace.
    fn come_back(h: &H, auth: &Auth, query: &str) -> Res {
        let r = h.call("GET", &format!("/sync/bamboohr/callback?{query}"), None, auth);
        assert_eq!(r.status, 302, "{}", r.body);
        r
    }

    fn back_with(state: &str) -> String {
        format!("code=c0de&state={}", urlencoding::encode(state))
    }

    fn redirected(finish: Finish) -> String {
        match finish {
            Finish::Redirect(url) => url,
            other => panic!("expected a redirect, got {other:?}"),
        }
    }

    fn bearer(token: &str) -> (String, String) {
        ("authorization".into(), format!("Bearer {token}"))
    }

    #[test]
    fn people_sync_signs_in_with_bamboohr() {
        let mut h = H::new();
        let (admin, admin_token) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let (bo_id, _) = h.user(&admin, "bo@acme.test", "Bo", "admin");
        let login = |h: &H, email: &str, password: &str| {
            session_from(&h.call("POST", "/api/v1/auth/login", Some(json!({ "email": email, "password": password })), &Auth::None))
        };
        let bo = login(&h, "bo@acme.test", "password123");
        with_key(&mut h);
        let fake = FakeBamboo::new(60);
        let answer = |c: &HttpCall| fake.answer(c);
        let settings = "https://kb.test/settings/people-sync";

        // Without the host's BambooHR app, signing in isn't offered; self-hosted, API keys are.
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["sign_in_available"].as_bool(), v["api_key_allowed"].as_bool()), (Some(false), Some(true)));
        assert_eq!(h.call("POST", "/api/v1/people-sync/sign-in", Some(json!({ "subdomain": "acme" })), &admin).status, 503);
        with_bamboohr_app(&mut h);
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["sign_in_available"], true);
        assert_eq!(h.call("POST", "/api/v1/people-sync/sign-in", Some(json!({ "subdomain": "acme" })), &mo).status, 403, "admins only");

        // BambooHR's sign-in page on the company's own domain, with the scopes a sync needs.
        let (url, state) = sign_in_link(&h, &admin, "https://Acme.bamboohr.com/home");
        assert!(
            url.starts_with("https://acme.bamboohr.com/authorize.php?request=authorize&response_type=code&client_id=bhr-client&"),
            "{url}"
        );
        assert!(url.contains("&redirect_uri=https%3A%2F%2Fkb.test%2Fsync%2Fbamboohr%2Fcallback&"), "{url}");
        assert!(
            url.ends_with(
                "&scope=openid+offline_access+employee+employee%3Acontact+employee%3Ajob+employee%3Aname+webhooks+webhooks.write"
            ),
            "{url}"
        );
        // Kept hashed.
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM people_sync_sign_ins WHERE state_hash = '{state}'")), 0);
        let hash = dumbslab_core::util::sha256_hex(&state);
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM people_sync_sign_ins WHERE state_hash = '{hash}'")), 1);

        // A made-up state goes nowhere; errors come back as codes only.
        let r = come_back(&h, &admin, "code=c0de&state=forged");
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=expired_link")));
        assert!(r.effects.is_empty());
        // Another browser session of the same admin can't finish it, and the link is spent.
        let other = login(&h, "ada@acme.test", "correct horse");
        let r = come_back(&h, &other, &back_with(&state));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=wrong_person")));
        assert!(r.effects.is_empty());
        let r = come_back(&h, &admin, &back_with(&state));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=expired_link")), "once only");
        // Nor another person.
        let (_, state) = sign_in_link(&h, &admin, "acme");
        let r = come_back(&h, &mo, &back_with(&state));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=wrong_person")));
        // An admin who lost the role meanwhile can't finish.
        let (_, state) = sign_in_link(&h, &bo, "acme");
        h.ok("PATCH", &format!("/api/v1/users/{bo_id}"), Some(json!({ "role": "member" })), &admin);
        let r = come_back(&h, &bo, &back_with(&state));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=not_admin")));
        // Too slow, or declined in BambooHR.
        let (_, state) = sign_in_link(&h, &admin, "acme");
        db_run(&h, |db| db.execute("UPDATE people_sync_sign_ins SET created_at = '2026-01-01T00:00:00.000Z'", &[]));
        let r = come_back(&h, &admin, &back_with(&state));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=too_slow")));
        let (_, state) = sign_in_link(&h, &admin, "acme");
        let r = come_back(&h, &admin, &format!("error=access_denied&state={}", urlencoding::encode(&state)));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=declined")));
        // BambooHR refusing the code saves nothing.
        fake.refuse("token", 400, json!({ "error": "invalid_grant" }));
        let (_, state) = sign_in_link(&h, &admin, "acme");
        let (finish, sent) = drive(&h, job_of(&come_back(&h, &admin, &back_with(&state))), &answer);
        assert_eq!(redirected(finish), format!("{settings}?people_sync_error=refused"));
        assert_eq!(sent.len(), 1);
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["configured"], false);
        fake.refuse.borrow_mut().clear();

        // Signing in: DumbSlab exchanges the code, checks access, adds the webhook and saves, then
        // sends the admin back to Settings.
        let (_, state) = sign_in_link(&h, &admin, "acme");
        let r = come_back(&h, &admin, &back_with(&state));
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        assert_eq!(redirected(finish), format!("{settings}?people_sync=connected"));
        assert_eq!((sent[0].method, sent[0].url.as_str()), ("POST", "https://acme.bamboohr.com/token.php?request=token"));
        let form = sent[0].body.clone().unwrap();
        for part in [
            "grant_type=authorization_code",
            "code=c0de",
            "redirect_uri=https%3A%2F%2Fkb.test%2Fsync%2Fbamboohr%2Fcallback",
            "client_id=bhr-client",
            "client_secret=bhr-secret",
        ] {
            assert!(form.contains(part), "{form}");
        }
        assert!(sent[1..].iter().all(|c| c.headers.contains(&bearer("at-1"))), "{sent:?}");
        assert!(sent.iter().any(|c| c.method == "POST" && c.url == "https://acme.bamboohr.com/api/v1/webhooks"));
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!(
            (v["auth"].as_str(), v["automatic_webhook"].as_bool(), v["subdomain"].as_str()),
            (Some("oauth"), Some(true), Some("acme"))
        );
        assert_eq!(h.ok("GET", "/api/v1/activity", None, &admin)["items"][0]["data"]["auth"], "oauth");
        // Tokens are sealed and never shown.
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync WHERE secret LIKE '%at-1%' OR secret LIKE '%rt-1%'"), 0);
        for r in [h.ok("GET", "/api/v1/people-sync", None, &admin), h.ok("GET", "/api/v1/activity", None, &admin)] {
            let text = r.to_string();
            assert!(!text.contains("at-1") && !text.contains("rt-1") && !text.contains("bhr-secret") && !text.contains("pk-60"), "{r}");
        }
        let r = come_back(&h, &admin, &back_with(&state));
        assert_eq!(r.header("location"), Some(&*format!("{settings}?people_sync_error=expired_link")), "once only");

        // Syncs use the sign-in, and so do BambooHR's webhook calls.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin_token);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].headers.contains(&bearer("at-1")));
        let r = people_hook(&h, "pk-60");
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // Shortly before the access token expires, a sync renews it first, and keeps the rest.
        let soon = |h: &H| {
            let at = dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::seconds(60));
            db_run(h, |db| db.execute("UPDATE people_sync SET expires_at = ?", &[at.into()]));
        };
        soon(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert_eq!((sent[0].method, sent[0].url.as_str()), ("POST", "https://acme.bamboohr.com/token.php?request=token"));
        let form = sent[0].body.clone().unwrap();
        assert!(
            form.contains("grant_type=refresh_token") && form.contains("refresh_token=rt-1") && form.contains("client_secret=bhr-secret")
        );
        assert!(sent[1].headers.contains(&bearer("at-2")));
        let later = dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::minutes(50));
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM people_sync WHERE expires_at > '{later}' AND refreshing_until IS NULL")), 1);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent.len() == 1 && sent[0].headers.contains(&bearer("at-2")), "renewed once: {sent:?}");
        let r = people_hook(&h, "pk-60");
        assert_eq!(r.status, 200, "the webhook's key survives renewal: {}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);
        // One renewal at a time: while another request renews an expired token, the sync waits.
        db_run(&h, |db| {
            db.execute(
                "UPDATE people_sync SET expires_at = '2026-01-01T00:00:00.000Z', refreshing_until = ?",
                &[format!("{} other", dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::seconds(30))).into()],
            )
        });
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent.is_empty() && matches!(&finish, Finish::Fail(e) if e.message.contains("renewing")), "{finish:?}");
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = NULL", &[]));
        // BambooHR refusing the renewal: sign in again.
        fake.refuse("token", 400, json!({ "error": "invalid_grant" }));
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &answer);
        assert!(matches!(&finish, Finish::Fail(e) if e.message.contains("Sign in with BambooHR again")), "{finish:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync WHERE refreshing_until IS NOT NULL"), 0, "the lease is let go");
        fake.refuse.borrow_mut().clear();
        soon(&h);

        // Saving again with the saved sign-in renews it, and keeps the webhook BambooHR still has.
        let (v, sent) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!(sent[0].url, "https://acme.bamboohr.com/token.php?request=token");
        assert!(!sent.iter().any(|c| c.method == "POST" && c.url.ends_with("/webhooks")), "kept: {sent:?}");
        assert!(sent.iter().any(|c| c.method == "GET" && c.url.ends_with("/webhooks/60") && c.headers.contains(&bearer("at-3"))));
        assert_eq!((v["auth"].as_str(), v["automatic_webhook"].as_bool()), (Some("oauth"), Some(true)));
        // A renewal under way when the sign-in is saved again may still store what it gets.
        let renewing = format!("{} other", dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::seconds(30)));
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = ?", &[renewing.clone().into()]));
        save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM people_sync WHERE refreshing_until = '{renewing}'")), 1);
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = NULL", &[]));
        // Another company needs its own sign-in.
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "other" })), &admin).status, 400);

        // Removing the sync deletes the webhook with the sign-in, renewed first when it's about to expire.
        soon(&h);
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        assert_eq!(filled(finish), json!({ "ok": true }));
        assert!(sent[0].body.as_deref().unwrap().contains("refresh_token=rt-3"), "{sent:?}");
        assert_eq!((sent[1].method, sent[1].url.as_str()), ("GET", "https://acme.bamboohr.com/api/v1/webhooks"));
        assert_eq!((sent[2].method, sent[2].url.as_str()), ("DELETE", "https://acme.bamboohr.com/api/v1/webhooks/60"));
        assert!(sent[1].headers.contains(&bearer("at-4")) && sent[2].headers.contains(&bearer("at-4")));
        assert!(fake.hooks.borrow().is_empty());
    }

    /// One step of a job, in its own transaction, like a host.
    fn people_step(h: &H, job: &mut Job, replies: Vec<HttpReply>) -> Step {
        h.store
            .with_tx(|db| {
                let (step, _) = connect::guarded_step(db, &h.cfg, job, replies, chrono::Utc::now(), |_| None);
                let ok = step.is_ok();
                (step, ok)
            })
            .unwrap()
            .unwrap()
    }

    fn fetched(step: Step) -> Vec<HttpCall> {
        match step {
            Step::Fetch(calls) => calls,
            Step::Done(f) => panic!("expected requests, got {f:?}"),
        }
    }

    fn failed_with(step: Step) -> dumbslab_core::ApiError {
        match step {
            Step::Done(Finish::Fail(e)) => e,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    /// A renewal's answer after its connection retired: that step only hands the tokens over (and
    /// is kept), and the next one stops.
    fn hands_over_then_stops(h: &H, job: &mut Job, replies: Vec<HttpReply>) -> dumbslab_core::ApiError {
        let step = people_step(h, job, replies);
        assert!(matches!(&step, Step::Fetch(calls) if calls.is_empty()), "{step:?}");
        failed_with(people_step(h, job, vec![]))
    }

    /// The job a request left to run after its response (the webhooks DumbSlab still has to delete).
    fn background_of(r: &Res) -> Job {
        r.effects
            .iter()
            .find_map(|e| match e {
                Effect::Background(j) => Some(j.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("a background job; got {} {}", r.status, r.body))
    }

    /// The access token stored for the people sync expires in a minute.
    fn expiring(h: &H) {
        let at = dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::seconds(60));
        db_run(h, |db| db.execute("UPDATE people_sync SET expires_at = ?", &[at.into()]));
    }

    /// Signs in with BambooHR for `company`: where the admin lands, the requests sent, and the
    /// callback's answer (with its cleanup job).
    fn bamboo_sign_in(h: &H, admin: &Auth, company: &str, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (String, Vec<HttpCall>, Res) {
        let (_, state) = sign_in_link(h, admin, company);
        let r = come_back(h, admin, &back_with(&state));
        let (finish, sent) = drive(h, job_of(&r), answer);
        (redirected(finish), sent, r)
    }

    /// One step that the host rolls back (the Worker refuses a step that grows a full workspace).
    fn people_step_rolled_back(h: &H, job: &mut Job, replies: Vec<HttpReply>) {
        let full = || Some(dumbslab_core::ApiError::new(507, "workspace_full", "The workspace is full."));
        let step = h
            .store
            .with_tx(|db| {
                let (step, _) = connect::guarded_step(db, &h.cfg, job, replies, chrono::Utc::now(), |_| full());
                let ok = step.is_ok();
                (step, ok)
            })
            .unwrap();
        assert!(step.is_err(), "rolled back");
    }

    /// The cleanup's waits are over: every record may run now.
    fn waits_over(h: &H) {
        db_run(h, |db| db.execute("UPDATE people_sync_cleanup SET next_attempt_at = '2026-01-01T00:00:00.000Z'", &[]));
    }

    fn records(h: &H) -> i64 {
        count(h, "SELECT COUNT(*) FROM people_sync_cleanup")
    }

    fn has_background(r: &Res) -> bool {
        r.effects.iter().any(|e| matches!(e, Effect::Background(_)))
    }

    /// The activity log's newest "gave up on old webhooks" event.
    fn abandoned(h: &H, admin: &Auth) -> Option<Value> {
        let items = h.ok("GET", "/api/v1/activity?limit=200", None, admin)["items"].clone();
        items.as_array().unwrap().iter().find(|e| e["event"] == "people_sync.webhook_abandoned").cloned()
    }

    #[test]
    fn people_sync_reconnecting_stops_work_under_way() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(80);
        let answer = |c: &HttpCall| fake.answer(c);
        let (landed, _, _) = bamboo_sign_in(&h, &admin, "acme", &answer);
        assert!(landed.ends_with("?people_sync=connected"), "{landed}");

        // A sync of acme is renewing its sign-in when an admin connects beta instead.
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut stale = job_of(&r);
        let calls = fetched(people_step(&h, &mut stale, vec![]));
        assert!(
            calls[0].url.starts_with("https://acme.bamboohr.com/token.php")
                && calls[0].body.as_deref().unwrap().contains("refresh_token=rt-1")
        );
        // Connecting beta waits while acme's sign-in is being renewed, by a new sign-in or a new key.
        let (_, state) = sign_in_link(&h, &admin, "beta");
        let r = come_back(&h, &admin, &back_with(&state));
        assert_eq!(r.header("location"), Some("https://kb.test/settings/people-sync?people_sync_error=busy"));
        assert!(r.effects.is_empty());
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "beta", "api_key": "k" })), &admin);
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("renewing"));
        // The renewal outlives its lease (a stalled host, say); then beta connects.
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = '2026-01-01T00:00:00.000Z x'", &[]));
        let (landed, sent, r) = bamboo_sign_in(&h, &admin, "beta", &answer);
        // acme's sign-in is about to expire, so its webhook is left to the cleanup, and Settings says so.
        assert!(landed.ends_with("?people_sync=connected&people_sync_notice=old_webhook"), "{landed}");
        assert!(!sent.iter().any(|c| c.method == "DELETE"), "{sent:?}");
        let cleanup = background_of(&r);
        // acme's renewal comes back: it lost its lease, so the sync stops and stores nothing.
        let renewed = answer(&calls[0]);
        let e = hands_over_then_stops(&h, &mut stale, vec![renewed.clone()]);
        assert!(e.message.contains("sign-in changed"), "{e:?}");
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["subdomain"].as_str(), v["webhook_cleanup"].as_i64()), (Some("beta"), Some(2)), "beta's and acme's credentials");
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent[0].url.starts_with("https://beta.bamboohr.com/api/v1/employees"), "{sent:?}");
        // The pass deletes acme's webhook with the tokens the stopped renewal handed over (BambooHR
        // may have spent the refresh token it had), and keeps beta's live one.
        let at = serde_json::from_str::<Value>(&renewed.body).unwrap()["access_token"].as_str().unwrap().to_string();
        let (_, sent) = drive(&h, cleanup, &answer);
        let delete = sent.iter().find(|c| c.method == "DELETE").unwrap();
        assert_eq!(delete.url, "https://acme.bamboohr.com/api/v1/webhooks/80");
        assert!(delete.headers.contains(&bearer(&at)), "{sent:?}");
        assert!(!sent.iter().any(|c| c.url.starts_with("https://acme.") && c.url.ends_with("/token.php?request=token")), "{sent:?}");
        assert_eq!(fake.ids(), ["81"]);
        assert_eq!(records(&h), 0);

        // A sync of beta is reading when an admin connects acme again: what it read is dropped.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut stale = job_of(&r);
        fetched(people_step(&h, &mut stale, vec![]));
        bamboo_sign_in(&h, &admin, "acme", &answer);
        let page =
            ok(json!({ "data": [employee("1", "Mo", "mo@acme.test", "Spy", "Beta", None)], "meta": { "page": { "nextCursor": null } } }));
        let e = failed_with(people_step(&h, &mut stale, vec![page]));
        assert!(e.message.contains("people sync changed"), "{e:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM user_profiles"), 0);

        // Removing the sync waits while a renewal is under way: it would spend the refresh token
        // that deleting the webhook needs.
        let lease = format!("{} other", dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::seconds(30)));
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = ?", &[lease.into()]));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("renewing"));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync"), 1);
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = NULL", &[]));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &answer);
        assert_eq!(filled(finish), json!({ "ok": true }));
        assert!(fake.ids().is_empty(), "every webhook is gone: {:?}", fake.ids());
    }

    #[test]
    fn people_sync_queued_sync_never_renews_into_a_new_connection() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(150);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);

        // A sync of acme, whose sign-in is about to expire, is queued; beta is connected before its
        // first step runs.
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut queued = job_of(&r);
        bamboo_sign_in(&h, &admin, "beta", &answer);
        // Its first step finds another connection: it renews nothing, and stores nothing.
        let e = failed_with(people_step(&h, &mut queued, vec![]));
        assert!(e.message.contains("sign-in changed"), "{e:?}");
        assert_eq!(fake.tokens.get(), 2, "acme's sign-in and beta's: no renewal");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync WHERE subdomain = 'beta' AND refreshing_until IS NULL"), 1);
        // beta's sign-in is untouched: a sync uses it.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent[0].url.starts_with("https://beta.bamboohr.com/") && sent[0].headers.contains(&bearer("at-2")), "{sent:?}");
    }

    #[test]
    fn people_sync_cleanup_renews_an_old_sign_in_after_switching_companies() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(90);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);
        db_run(&h, |db| db.execute("UPDATE people_sync SET expires_at = '2026-01-01T00:00:00.000Z'", &[]));

        // acme's access token has expired. Connecting beta can't delete acme's webhook now: acme's
        // credentials, refresh token included, are kept for the cleanup (sealed), and Settings says so.
        let (landed, sent, r) = bamboo_sign_in(&h, &admin, "beta", &answer);
        assert!(landed.ends_with("&people_sync_notice=old_webhook"), "{landed}");
        assert!(!sent.iter().any(|c| c.url.starts_with("https://acme.")), "{sent:?}");
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["webhook_cleanup"], 2);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE secret LIKE '%rt-1%'"), 0, "sealed");
        // The pass renews acme's sign-in, lists acme's webhooks, and deletes this workspace's.
        let (_, sent) = drive(&h, background_of(&r), &answer);
        let at = |m: &str, u: &str| sent.iter().position(|c| c.method == m && c.url == u).unwrap_or_else(|| panic!("{m} {u}: {sent:?}"));
        let (renew, list, delete) = (
            at("POST", "https://acme.bamboohr.com/token.php?request=token"),
            at("GET", "https://acme.bamboohr.com/api/v1/webhooks"),
            at("DELETE", "https://acme.bamboohr.com/api/v1/webhooks/90"),
        );
        assert!(renew < list && list < delete);
        assert!(sent[renew].body.as_deref().unwrap().contains("refresh_token=rt-1"));
        assert!(!sent[delete].headers.contains(&bearer("at-1")));
        assert_eq!(fake.ids(), ["91"], "beta's live webhook stays");
        assert_eq!(records(&h), 0);
        // With nothing left, syncs and Settings schedule no pass.
        assert!(!has_background(&h.call("GET", "/api/v1/people-sync", None, &admin)));
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        assert!(!has_background(&r));
        drive(&h, job_of(&r), &answer);
    }

    #[test]
    fn people_sync_cleanup_finds_webhooks_whose_ids_were_lost() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(100);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);

        // A new key replaces the webhook, and the host rolls back the step that read BambooHR's
        // answers: the new webhook's id is lost with it.
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-2" })), &admin);
        let mut job = job_of(&r);
        let calls = fetched(people_step(&h, &mut job, vec![]));
        let calls = fetched(people_step(&h, &mut job, calls.iter().map(answer).collect()));
        people_step_rolled_back(&h, &mut job, calls.iter().map(answer).collect());
        assert_eq!(fake.ids(), ["101"], "BambooHR deleted the old one and added the new one");
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["automatic_webhook"], true, "as before the save");
        assert_eq!(records(&h), 2, "both keys were recorded before BambooHR changed");
        // The save's lease runs out (the rolled-back step held it).
        db_run(&h, |db| db.execute("UPDATE settings SET value = '2026-01-01T00:00:00.000Z x' WHERE key = 'people_sync_saving'", &[]));

        // A pass with each key lists acme's webhooks and deletes the untracked one, and says the
        // saved one is gone.
        let (_, sent) = drive(&h, background_of(&r), &answer);
        let delete = sent.iter().find(|c| c.method == "DELETE").unwrap();
        assert_eq!(delete.url, "https://acme.bamboohr.com/api/v1/webhooks/101");
        assert!(fake.ids().is_empty());
        assert_eq!(records(&h), 0);
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!(v["webhook"], false);
        assert!(v["webhook_error"].as_str().unwrap().contains("stopped partway"), "{v}");
        // Saving again adds a webhook again.
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!((v["automatic_webhook"].as_bool(), &v["webhook_error"]), (Some(true), &Value::Null));
    }

    #[test]
    fn people_sync_removal_retries_with_backoff_until_bamboohr_answers() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(120);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);
        let waits = |h: &H, secs: i64| {
            let at = dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::seconds(secs));
            count(h, &format!("SELECT COUNT(*) FROM people_sync_cleanup WHERE next_attempt_at > '{at}'"))
        };

        // BambooHR has an error while the sync is removed: the sync is gone, its webhook is kept for
        // the cleanup, and the answer says so.
        fake.refuse("list", 500, json!(null));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert!(v["notice"].as_str().unwrap().contains("tries again"), "{v}");
        assert_eq!((records(&h), waits(&h, 50), waits(&h, 70)), (1, 1, 0), "a minute's wait");
        // Until then, opening Settings or an unknown delivery runs nothing.
        assert!(!has_background(&h.call("GET", "/api/v1/people-sync", None, &admin)));
        let r = people_hook(&h, "pk-120");
        assert_eq!(r.status, 404);
        assert!(!has_background(&r));
        // Then opening Settings runs a pass. BambooHR times out: the wait doubles.
        waits_over(&h);
        fake.refuse("list", 0, json!(null));
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        drive(&h, background_of(&r), &answer);
        assert_eq!((records(&h), waits(&h, 110), waits(&h, 130)), (1, 1, 0), "two minutes");
        // BambooHR is back. The orphaned webhook's next delivery prompts the pass that deletes it.
        fake.refuse.borrow_mut().clear();
        waits_over(&h);
        let r = people_hook(&h, "pk-120");
        assert_eq!(r.status, 404, "turned away");
        let (_, sent) = drive(&h, background_of(&r), &answer);
        assert_eq!(sent.last().map(|c| (c.method, c.url.as_str())), Some(("DELETE", "https://acme.bamboohr.com/api/v1/webhooks/120")));
        assert!(fake.ids().is_empty());
        assert_eq!(records(&h), 0);
        assert!(abandoned(&h, &admin).is_none());
    }

    #[test]
    fn people_sync_cleanup_gives_up_only_on_dead_credentials_or_after_thirty_days() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(130);
        let answer = |c: &HttpCall| fake.answer(c);
        let pass = |h: &H| {
            waits_over(h);
            let r = h.call("GET", "/api/v1/people-sync", None, &admin);
            drive(h, background_of(&r), &answer);
        };
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);
        fake.refuse("list", 503, json!(null));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        drive(&h, job_of(&r), &answer);

        // Timeouts, rate limits and BambooHR's own errors never end it, however many.
        db_run(&h, |db| db.execute("UPDATE people_sync_cleanup SET failures = 40", &[]));
        for status in [503, 429, 0, 502] {
            fake.refuse("list", status, json!(null));
            pass(&h);
            assert_eq!(records(&h), 1, "after HTTP {status}");
        }
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE failures = 44"), 1);
        assert!(abandoned(&h, &admin).is_none());
        // After 30 days DumbSlab gives up, names the webhook and the company for an admin, and
        // forgets the credentials.
        db_run(&h, |db| db.execute("UPDATE people_sync_cleanup SET created_at = '2026-09-01T00:00:00.000Z'", &[]));
        pass(&h);
        assert_eq!(records(&h), 0);
        let event = abandoned(&h, &admin).expect("an activity event");
        let summary = event["summary"].as_str().unwrap();
        assert!(summary.contains("30 days") && summary.contains("webhook 130") && summary.contains("acme.bamboohr.com"), "{summary}");
        assert_eq!(event["data"]["webhook_ids"], json!(["130"]));
        db_run(&h, |db| db.execute("DELETE FROM activity WHERE event = 'people_sync.webhook_abandoned'", &[]));
        fake.refuse.borrow_mut().clear();

        // An API key BambooHR refuses is dead: DumbSlab gives up at once.
        save_people(&h, &admin, json!({ "subdomain": "beta", "api_key": "key-2" }), &answer);
        fake.refuse("list", 401, json!(null));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        drive(&h, job_of(&r), &answer);
        assert_eq!(records(&h), 0);
        let summary = abandoned(&h, &admin).unwrap()["summary"].as_str().unwrap().to_string();
        assert!(summary.contains("HTTP 401") && summary.contains("webhook 131") && summary.contains("beta.bamboohr.com"), "{summary}");
        db_run(&h, |db| db.execute("DELETE FROM activity WHERE event = 'people_sync.webhook_abandoned'", &[]));
        fake.refuse.borrow_mut().clear();

        // So is a sign-in BambooHR won't renew, the second time: a renewal still under way when the
        // sync was removed could have handed over new tokens.
        bamboo_sign_in(&h, &admin, "gamma", &answer);
        db_run(&h, |db| db.execute("UPDATE people_sync SET expires_at = '2026-01-01T00:00:00.000Z'", &[]));
        fake.refuse("token", 400, json!({ "error": "invalid_grant" }));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        drive(&h, job_of(&r), &answer);
        assert_eq!(records(&h), 1, "once: wait");
        assert!(abandoned(&h, &admin).is_none());
        pass(&h);
        assert_eq!(records(&h), 0);
        let summary = abandoned(&h, &admin).unwrap()["summary"].as_str().unwrap().to_string();
        assert!(
            summary.contains("refused to renew") && summary.contains("webhook 132") && summary.contains("gamma.bamboohr.com"),
            "{summary}"
        );
    }

    #[test]
    fn people_sync_a_finishing_pass_keeps_work_queued_meanwhile() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(41);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);
        // An orphan of this workspace's next to the live webhook 41.
        let tag = db_run(&h, |db| dumbslab_core::ops::admin::setting(db, "people_sync_tag")).unwrap();
        let orphan = (String::from("acme"), String::from("https://kb.test/hooks/people"), format!("DumbSlab people sync (kb.test) {tag}"));
        fake.hooks.borrow_mut().insert("40".into(), orphan);

        // A pass is deleting orphan 40, and keeps live webhook 41.
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let mut pass = background_of(&r);
        let calls = fetched(people_step(&h, &mut pass, vec![]));
        let calls = fetched(people_step(&h, &mut pass, calls.iter().map(answer).collect()));
        assert_eq!(calls.iter().map(|c| c.url.as_str()).collect::<Vec<_>>(), ["https://acme.bamboohr.com/api/v1/webhooks/40"]);
        // Meanwhile the sync is removed: its connection is recorded again, now for 41 too. The pass
        // holds the record, so removal's own pass leaves it.
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert!(v["notice"].as_str().unwrap().contains("tries again"), "{v}");
        // The first pass ends: the record was recorded again meanwhile, so it stays for the next one.
        let step = people_step(&h, &mut pass, calls.iter().map(answer).collect());
        assert!(matches!(step, Step::Done(Finish::Fill(_))), "{step:?}");
        assert_eq!(fake.ids(), ["41"]);
        assert_eq!((records(&h), count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE working_until IS NULL")), (1, 1));
        // The next pass deletes 41.
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let (_, sent) = drive(&h, background_of(&r), &answer);
        assert!(sent.iter().any(|c| c.method == "DELETE" && c.url.ends_with("/webhooks/41")), "{sent:?}");
        assert!(fake.ids().is_empty());
        assert_eq!(records(&h), 0);
    }

    #[test]
    fn people_sync_cleanup_keeps_the_tokens_a_fenced_renewal_got() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(160);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);

        // A pass renews acme, the live sign-in.
        expiring(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let mut pass = background_of(&r);
        let calls = fetched(people_step(&h, &mut pass, vec![]));
        assert!(calls[0].url.starts_with("https://acme.bamboohr.com/token.php"));
        assert!(calls[0].body.as_deref().unwrap().contains("refresh_token=rt-1"));
        // Its renewal outlives its lease, and beta is connected before BambooHR answers.
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = '2026-01-01T00:00:00.000Z x'", &[]));
        let (_, _, connected) = bamboo_sign_in(&h, &admin, "beta", &answer);
        // BambooHR renews acme. Fenced off from the saved sign-in (beta's now), the tokens go to
        // acme's record, and the pass leaves it for the next one: no giving up.
        let renewed = answer(&calls[0]);
        let at = serde_json::from_str::<Value>(&renewed.body).unwrap()["access_token"].as_str().unwrap().to_string();
        let step = people_step(&h, &mut pass, vec![renewed]);
        assert!(matches!(&step, Step::Fetch(calls) if calls.is_empty()), "{step:?}");
        let step = people_step(&h, &mut pass, vec![]);
        assert!(matches!(step, Step::Done(Finish::Fill(_))), "{step:?}");
        assert!(abandoned(&h, &admin).is_none());
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme' AND working_until IS NULL"), 1);
        // The connect's own pass deletes acme's webhook with the handed-over tokens: no renewal.
        let (_, sent) = drive(&h, background_of(&connected), &answer);
        assert!(!sent.iter().any(|c| c.url.ends_with("/token.php?request=token")), "{sent:?}");
        let delete = sent.iter().find(|c| c.method == "DELETE").unwrap();
        assert_eq!(delete.url, "https://acme.bamboohr.com/api/v1/webhooks/160");
        assert!(delete.headers.contains(&bearer(&at)));
        assert_eq!(fake.ids(), ["161"], "beta's live webhook stays");
        assert_eq!(records(&h), 0);
        assert!(abandoned(&h, &admin).is_none());
    }

    #[test]
    fn people_sync_a_renewal_that_outlived_its_lease_still_stores_its_tokens() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(180);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);

        // A cleanup pass renews the saved sign-in: BambooHR spends rt-1 and answers with rt-2, but
        // the pass stalls past its lease.
        expiring(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let mut pass = background_of(&r);
        let calls = fetched(people_step(&h, &mut pass, vec![]));
        assert!(calls[0].body.as_deref().unwrap().contains("refresh_token=rt-1"));
        let renewed = answer(&calls[0]);
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = '2026-01-01T00:00:00.000Z x'", &[]));
        // A sync takes over the renewal with rt-1, and BambooHR refuses: it was spent.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut sync = job_of(&r);
        let sent = fetched(people_step(&h, &mut sync, vec![]));
        assert!(sent[0].body.as_deref().unwrap().contains("refresh_token=rt-1"));
        let refused = HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() };
        failed_with(people_step(&h, &mut sync, vec![refused]));
        // The pass resumes. The saved sign-in still holds the refresh token it spent, so the new
        // tokens land there.
        let calls = fetched(people_step(&h, &mut pass, vec![renewed]));
        assert!(calls[0].headers.contains(&bearer("at-2")), "{calls:?}");
        people_step(&h, &mut pass, calls.iter().map(answer).collect());
        // The sync works with them, and renews with rt-2 next time.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert!(sent.len() == 1 && sent[0].headers.contains(&bearer("at-2")), "{sent:?}");
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert!(sent[0].body.as_deref().unwrap().contains("refresh_token=rt-2"), "{sent:?}");
        // A renewal that ends after another advanced the tokens keeps those.
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut slow = job_of(&r);
        let calls = fetched(people_step(&h, &mut slow, vec![]));
        let late = answer(&calls[0]);
        // It stalls past its leases, and another sync renews meanwhile.
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = NULL, running_until = NULL", &[]));
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        let newest = sent[1].headers.iter().find(|(k, _)| k == "authorization").unwrap().1.clone();
        let calls = fetched(people_step(&h, &mut slow, vec![late]));
        assert_eq!(calls[0].headers.iter().find(|(k, _)| k == "authorization").unwrap().1, newest, "the newer tokens");
    }

    #[test]
    fn people_sync_cleanup_keeps_each_connections_tokens_its_own() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(200);
        let answer = |c: &HttpCall| fake.answer(c);
        // acme and then beta are signed in with the same refresh token value (rt-1), and both
        // retired: gamma is the saved sign-in now.
        bamboo_sign_in(&h, &admin, "acme", &answer);
        fake.tokens.set(0);
        bamboo_sign_in(&h, &admin, "beta", &answer);
        bamboo_sign_in(&h, &admin, "gamma", &answer);
        let acme = "subdomain = 'acme'";
        let beta = "subdomain = 'beta'";
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM people_sync_cleanup WHERE {acme} OR {beta}")), 2);
        // A pass renews acme's copy, and only acme's: beta's waits.
        db_run(&h, |db| {
            db.execute(&format!("UPDATE people_sync_cleanup SET expires_at = '2026-01-01T00:00:00.000Z' WHERE {acme}"), &[])?;
            db.execute("UPDATE people_sync_cleanup SET next_attempt_at = '2099-01-01T00:00:00.000Z' WHERE subdomain <> 'acme'", &[])
        });
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let (_, sent) = drive(&h, background_of(&r), &answer);
        assert!(sent[0].url.starts_with("https://acme.") && sent[0].body.as_deref().unwrap().contains("refresh_token=rt-1"), "{sent:?}");
        // beta's record still holds beta's own tokens: its pass uses them.
        db_run(&h, |db| db.execute(&format!("UPDATE people_sync_cleanup SET next_attempt_at = NULL WHERE {beta}"), &[]));
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let (_, sent) = drive(&h, background_of(&r), &answer);
        let list = sent.iter().find(|c| c.url == "https://beta.bamboohr.com/api/v1/webhooks").unwrap();
        assert!(list.headers.contains(&bearer("at-1")), "{sent:?}");
        assert!(!fake.ids().iter().any(|id| id == "201"), "beta's old webhook is gone: {:?}", fake.ids());
    }

    #[test]
    fn people_sync_a_stalled_pass_never_disables_a_new_webhook() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(210);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);

        // A pass lists acme's webhooks (210, live), then stalls.
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let mut pass = background_of(&r);
        let calls = fetched(people_step(&h, &mut pass, vec![]));
        let listed: Vec<HttpReply> = calls.iter().map(answer).collect();
        // Meanwhile a new key for the same company replaces the webhook with 211.
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-2" }), &answer);
        assert_eq!(v["automatic_webhook"], true);
        assert_eq!(fake.ids(), ["211"]);
        // The pass resumes with its old list, which lacks 211: it leaves everything to the next pass.
        let step = people_step(&h, &mut pass, listed);
        assert!(matches!(step, Step::Done(Finish::Fill(_))), "{step:?}");
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["automatic_webhook"].as_bool(), &v["webhook_error"]), (Some(true), &Value::Null), "{v}");
        let r = people_hook(&h, "pk-211");
        assert_eq!(r.status, 200, "the new webhook still works: {}", r.body);
        drive(&h, job_of(&r), &answer);
        assert_eq!(fake.ids(), ["211"]);
    }

    /// One step under a guard that refuses it (a full workspace): its answer, and whether it was
    /// kept.
    fn people_step_on_a_full_workspace(h: &H, job: &mut Job, replies: Vec<HttpReply>) -> dumbslab_core::ApiResult<Step> {
        let full = || Some(dumbslab_core::ApiError::new(507, "workspace_full", "The workspace is full."));
        h.store
            .with_tx(|db| {
                let (step, _) = connect::guarded_step(db, &h.cfg, job, replies, chrono::Utc::now(), |_| full());
                let ok = step.is_ok();
                (step, ok)
            })
            .unwrap()
    }

    #[test]
    fn people_sync_keeps_renewed_tokens_on_a_full_workspace() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        h.user(&admin, "mo@acme.test", "Mo", "member");
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(220);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);

        // A sync renews the sign-in on a full workspace. The step that stores the renewed tokens is
        // kept, though the host refuses steps that grow storage: BambooHR has spent rt-1 already.
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut sync = job_of(&r);
        let calls = fetched(people_step(&h, &mut sync, vec![]));
        let step = people_step_on_a_full_workspace(&h, &mut sync, calls.iter().map(answer).collect());
        let pages = match step {
            Ok(Step::Fetch(pages)) => pages,
            other => panic!("kept: {other:?}"),
        };
        assert!(pages[0].headers.contains(&bearer("at-2")));
        // The next step, which writes profiles, is refused and rolled back as usual.
        let page =
            ok(json!({ "data": [employee("1", "Mo", "mo@acme.test", "Spy", "Ops", None)], "meta": { "page": { "nextCursor": null } } }));
        assert!(people_step_on_a_full_workspace(&h, &mut sync, vec![page]).is_err());
        assert_eq!(count(&h, "SELECT COUNT(*) FROM user_profiles"), 0);
        db_run(&h, |db| db.execute("UPDATE people_sync SET running_until = NULL", &[]));
        // The renewed tokens are stored: the next sync uses them, and renews with rt-2.
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent.len() == 1 && sent[0].headers.contains(&bearer("at-2")), "{sent:?}");
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent[0].body.as_deref().unwrap().contains("refresh_token=rt-2"), "{sent:?}");

        // So does a cleanup pass renewing a retired sign-in's copy.
        db_run(&h, |db| db.execute("UPDATE people_sync SET expires_at = '2026-01-01T00:00:00.000Z'", &[]));
        let (_, _, connected) = bamboo_sign_in(&h, &admin, "beta", &answer);
        let mut pass = background_of(&connected);
        let calls = fetched(people_step(&h, &mut pass, vec![]));
        assert!(calls[0].url.starts_with("https://acme.") && calls[0].url.ends_with("/token.php?request=token"));
        let renewed = calls.iter().map(answer).collect();
        assert!(matches!(people_step_on_a_full_workspace(&h, &mut pass, renewed), Ok(Step::Fetch(_))));
        let acme = count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme' AND expires_at > '2026-06-01'");
        assert_eq!(acme, 1, "acme's renewed copy is stored");
    }

    #[test]
    fn people_sync_cleanup_waits_for_the_hosts_bamboohr_app() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(230);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);
        db_run(&h, |db| db.execute("UPDATE people_sync SET expires_at = '2026-01-01T00:00:00.000Z'", &[]));

        // The host's BambooHR app goes missing (a deploy without it, say), and the sync is removed:
        // the sign-in can't be renewed now, so the cleanup waits and keeps the credentials.
        let app = h.cfg.connectors.apps.remove("bamboohr").unwrap();
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert!(v["notice"].as_str().unwrap().contains("tries again"), "{v}");
        assert_eq!(records(&h), 1);
        assert!(abandoned(&h, &admin).is_none());
        // It's back: the next pass renews, and deletes the webhook.
        h.cfg.connectors.apps.insert("bamboohr".into(), app);
        waits_over(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let (_, sent) = drive(&h, background_of(&r), &answer);
        assert!(sent[0].url.ends_with("/token.php?request=token"), "{sent:?}");
        assert!(fake.ids().is_empty());
        assert_eq!(records(&h), 0);
        assert!(abandoned(&h, &admin).is_none());
    }

    #[test]
    fn people_sync_a_save_stalled_past_its_lease_cant_bring_back_a_removed_sync() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(240);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);

        // A save with a new key starts, and stalls past its lease.
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-2" })), &admin);
        let mut stalled = job_of(&r);
        let calls = fetched(people_step(&h, &mut stalled, vec![]));
        db_run(&h, |db| db.execute("UPDATE settings SET value = '2026-01-01T00:00:00.000Z x' WHERE key = 'people_sync_saving'", &[]));
        // Meanwhile the sync is removed.
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        drive(&h, job_of(&r), &answer);
        assert!(fake.ids().is_empty());
        // The stalled save resumes: it no longer holds its lease, so it changes nothing.
        let e = failed_with(people_step(&h, &mut stalled, calls.iter().map(answer).collect()));
        assert_eq!(e.status, 409);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync"), 0, "the sync stays removed");
        assert!(fake.ids().is_empty(), "no webhook added");
    }

    #[test]
    fn people_sync_keeps_handed_over_tokens_on_a_full_workspace() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(260);
        let answer = |c: &HttpCall| fake.answer(c);
        let acme_renewed = |h: &H, at: &str| {
            let sql = format!("SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme' AND expires_at > '{at}'");
            count(h, &sql)
        };
        let later = dumbslab_core::util::ts(chrono::Utc::now() + chrono::Duration::minutes(50));

        // A sync's renewal outlives its lease, and beta is connected meanwhile. On a full workspace,
        // the step that hands the renewed tokens to acme's record is kept.
        bamboo_sign_in(&h, &admin, "acme", &answer);
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut sync = job_of(&r);
        let calls = fetched(people_step(&h, &mut sync, vec![]));
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = '2026-01-01T00:00:00.000Z x'", &[]));
        bamboo_sign_in(&h, &admin, "beta", &answer);
        assert_eq!(acme_renewed(&h, &later), 0);
        let step = people_step_on_a_full_workspace(&h, &mut sync, calls.iter().map(answer).collect());
        assert!(matches!(&step, Ok(Step::Fetch(calls)) if calls.is_empty()), "kept: {step:?}");
        assert_eq!(acme_renewed(&h, &later), 1, "acme's record holds the renewed tokens");
        assert!(people_step_on_a_full_workspace(&h, &mut sync, vec![]).is_err(), "the next step is refused as usual");
        assert_eq!(acme_renewed(&h, &later), 1);
        db_run(&h, |db| db.execute("DELETE FROM people_sync_cleanup", &[]));

        // So does a save's: a save of beta again renews beta's sign-in, stalls past its leases, and
        // gamma is connected meanwhile.
        expiring(&h);
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "beta" })), &admin);
        let mut save = job_of(&r);
        let calls = fetched(people_step(&h, &mut save, vec![]));
        assert!(calls[0].url.starts_with("https://beta.") && calls[0].url.ends_with("/token.php?request=token"), "{calls:?}");
        db_run(&h, |db| {
            db.execute("UPDATE people_sync SET refreshing_until = '2026-01-01T00:00:00.000Z x'", &[])?;
            db.execute("UPDATE settings SET value = '2026-01-01T00:00:00.000Z x' WHERE key = 'people_sync_saving'", &[])
        });
        bamboo_sign_in(&h, &admin, "gamma", &answer);
        let beta_renewed = format!("SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'beta' AND expires_at > '{later}'");
        assert_eq!(count(&h, &beta_renewed), 0);
        let step = people_step_on_a_full_workspace(&h, &mut save, calls.iter().map(answer).collect());
        assert!(matches!(&step, Ok(Step::Fetch(calls)) if calls.is_empty()), "kept: {step:?}");
        assert_eq!(count(&h, &beta_renewed), 1, "beta's record holds the renewed tokens");
        let e = failed_with(people_step(&h, &mut save, vec![]));
        assert_eq!(e.status, 409);
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["subdomain"], "gamma");
    }

    #[test]
    fn people_sync_a_stalled_save_leaves_newer_cleanup_work() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(250);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        drive(&h, background_of(&r), &answer);
        assert_eq!(records(&h), 0);

        // Save A moves to beta (retiring acme's connection), sends its changes, and stalls past its lease.
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "beta", "api_key": "key-2" })), &admin);
        let mut stalled = job_of(&r);
        let calls = fetched(people_step(&h, &mut stalled, vec![]));
        let changes = fetched(people_step(&h, &mut stalled, calls.iter().map(answer).collect()));
        db_run(&h, |db| db.execute("UPDATE settings SET value = '2026-01-01T00:00:00.000Z x' WHERE key = 'people_sync_saving'", &[]));
        // Save B recreates acme's webhook with key-1, then the sync is removed while BambooHR is
        // down: acme's credentials are recorded again, and wait.
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);
        fake.refuse("list", 500, json!(null));
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        drive(&h, job_of(&r), &answer);
        fake.refuse.borrow_mut().clear();
        let acme = "SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme'";
        let before = count(&h, acme);
        assert!(before >= 2, "B's and the removal's: {before}");
        // A resumes: BambooHR answers its changes, but it no longer holds its lease. It changes
        // nothing here, and drops none of the newer records.
        let e = failed_with(people_step(&h, &mut stalled, changes.iter().map(answer).collect()));
        assert_eq!(e.status, 409);
        assert_eq!(count(&h, acme), before);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync"), 0, "still removed");
        // The cleanup deletes every webhook left: acme's and the one A added for beta.
        waits_over(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        drive(&h, background_of(&r), &answer);
        assert!(fake.ids().is_empty(), "{:?}", fake.ids());
    }

    #[test]
    fn people_sync_a_late_pass_leaves_a_record_made_anew() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let fake = FakeBamboo::new(190);
        let answer = |c: &HttpCall| fake.answer(c);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);

        // A pass takes the record and stalls past its lease; another pass ends it.
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let mut late = background_of(&r);
        fetched(people_step(&h, &mut late, vec![]));
        db_run(&h, |db| db.execute("UPDATE people_sync_cleanup SET working_until = '2026-01-01T00:00:00.000Z x'", &[]));
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        drive(&h, background_of(&r), &answer);
        assert_eq!(records(&h), 0);
        // The sync is removed: the same connection is recorded anew, at the first version again.
        let r = h.call("DELETE", "/api/v1/people-sync", None, &admin);
        assert_eq!(r.status, 200);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE version = 0"), 1);
        // The late pass ends: the new record isn't its to drop.
        let step = people_step(&h, &mut late, vec![ok(json!({ "webhooks": [] }))]);
        assert!(matches!(step, Step::Done(Finish::Fill(_))), "{step:?}");
        assert_eq!(records(&h), 1);
        // Removal's pass deletes the webhook.
        drive(&h, job_of(&r), &answer);
        assert!(fake.ids().is_empty());
        assert_eq!(records(&h), 0);
    }

    #[test]
    fn people_sync_cleanup_waits_for_a_renewal_still_under_way() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(170);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);

        // A sync has sent acme's refresh token when the admin connects beta (the renewal outlived
        // its lease). The save keeps a copy of acme's credentials for the cleanup.
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let mut sync = job_of(&r);
        fetched(people_step(&h, &mut sync, vec![]));
        db_run(&h, |db| db.execute("UPDATE people_sync SET refreshing_until = '2026-01-01T00:00:00.000Z x'", &[]));
        let (_, _, connected) = bamboo_sign_in(&h, &admin, "beta", &answer);
        // The cleanup renews the copy first. BambooHR refuses (the sync's renewal spent that refresh
        // token): DumbSlab waits instead of giving up.
        fake.refuse("token", 400, json!({ "error": "invalid_grant" }));
        drive(&h, background_of(&connected), &answer);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme' AND refused = 1"), 1);
        assert!(abandoned(&h, &admin).is_none());
        // Another pass renews the copy again (rt-1 still); meanwhile the sync's renewal comes back: it
        // stops, and hands its new tokens to acme's record.
        waits_over(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let mut again = background_of(&r);
        let calls = fetched(people_step(&h, &mut again, vec![]));
        assert!(calls.iter().any(|c| c.body.as_deref().is_some_and(|b| b.contains("refresh_token=rt-1"))), "{calls:?}");
        let renewed = ok(json!({ "access_token": "at-late", "refresh_token": "rt-late", "expires_in": 3600 }));
        let e = hands_over_then_stops(&h, &mut sync, vec![renewed]);
        assert!(e.message.contains("sign-in changed"), "{e:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme' AND refused = 0"), 1);
        // BambooHR refuses that pass's renewal (rt-1, already spent). The record holds other tokens
        // now: no giving up, though it was refused before.
        let answers: Vec<HttpReply> = calls.iter().map(answer).collect();
        // The step reading renewals stores only credentials; the refusal is dealt with in the next.
        let step = people_step(&h, &mut again, answers);
        assert!(matches!(&step, Step::Fetch(calls) if calls.is_empty()), "{step:?}");
        people_step(&h, &mut again, vec![]);
        assert!(abandoned(&h, &admin).is_none());
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync_cleanup WHERE subdomain = 'acme'"), 1);
        // The next pass needs no renewal: it deletes acme's webhook with those tokens.
        fake.refuse.borrow_mut().clear();
        waits_over(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        let (_, sent) = drive(&h, background_of(&r), &answer);
        let delete = sent.iter().find(|c| c.method == "DELETE").unwrap();
        assert_eq!(delete.url, "https://acme.bamboohr.com/api/v1/webhooks/170");
        assert!(delete.headers.contains(&bearer("at-late")));
        assert!(!sent.iter().any(|c| c.url.starts_with("https://acme.") && c.url.ends_with("/token.php?request=token")));
        assert_eq!(fake.ids(), ["171"]);
        assert_eq!(records(&h), 0);
        assert!(abandoned(&h, &admin).is_none());
    }

    #[test]
    fn people_sync_cleanup_renews_the_saved_sign_in_through_its_lease() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_bamboohr_app(&mut h);
        let fake = FakeBamboo::new(110);
        let answer = |c: &HttpCall| fake.answer(c);
        bamboo_sign_in(&h, &admin, "acme", &answer);

        // Saved again with the same sign-in, BambooHR wouldn't look up or delete the old webhook: a
        // new one is added, and the cleanup has the old one to delete.
        fake.refuse("get", 500, json!(null));
        fake.refuse("delete", 500, json!(null));
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme" })), &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert!(v["notice"].as_str().unwrap().contains("tries again"), "{v}");
        assert_eq!(fake.ids(), ["110", "111"]);
        // The sign-in is about to expire. The pass renews the saved sign-in itself, through its
        // renewal lease, and stores the new tokens; it never renews a copy.
        expiring(&h);
        let (_, sent) = drive(&h, background_of(&r), &answer);
        assert!(sent[0].body.as_deref().unwrap().contains("refresh_token=rt-1"), "{sent:?}");
        assert!(sent[1..].iter().all(|c| c.headers.contains(&bearer("at-2"))), "{sent:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM people_sync WHERE refreshing_until IS NULL"), 1);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent.len() == 1 && sent[0].headers.contains(&bearer("at-2")), "the sync uses the renewed tokens: {sent:?}");
        // BambooHR is back: the next pass deletes the old webhook, and keeps the live one.
        fake.refuse.borrow_mut().clear();
        waits_over(&h);
        let r = h.call("GET", "/api/v1/people-sync", None, &admin);
        drive(&h, background_of(&r), &answer);
        assert_eq!(fake.ids(), ["111"]);
        assert_eq!(records(&h), 0);
        // The sync's own renewals still work: nothing else spent its refresh token.
        expiring(&h);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert!(sent[0].body.as_deref().unwrap().contains("refresh_token=rt-2"), "{sent:?}");
    }

    #[test]
    fn people_sync_loses_no_webhook_when_the_admin_is_demoted_mid_save() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let (bo_id, _) = h.user(&admin, "bo@acme.test", "Bo", "admin");
        let bo = session_from(&h.call(
            "POST",
            "/api/v1/auth/login",
            Some(json!({ "email": "bo@acme.test", "password": "password123" })),
            &Auth::None,
        ));
        with_key(&mut h);
        let fake = FakeBamboo::new(100);
        let answer = |c: &HttpCall| fake.answer(c);
        let role = |r: &str| h.ok("PATCH", &format!("/api/v1/users/{bo_id}"), Some(json!({ "role": r })), &admin);
        save_people(&h, &admin, json!({ "subdomain": "acme", "api_key": "key-1" }), &answer);

        // Demoted before DumbSlab changes anything in BambooHR: the save stops there.
        let before = records(&h);
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-2" })), &bo);
        let mut job = job_of(&r);
        let calls = fetched(people_step(&h, &mut job, vec![]));
        role("member");
        let e = failed_with(people_step(&h, &mut job, calls.iter().map(answer).collect()));
        assert_eq!(e.status, 403);
        assert_eq!(fake.ids(), ["100"], "nothing changed in BambooHR");
        assert_eq!(records(&h), before, "nor recorded");
        assert_eq!(h.ok("GET", "/api/v1/people-sync", None, &admin)["automatic_webhook"], true);
        role("admin");

        // Demoted while BambooHR deletes the old webhook and adds the new one: Settings says the old
        // one is gone, and the pass deletes the new one, which nothing keeps.
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "key-2" })), &bo);
        let mut job = job_of(&r);
        let cleanup = background_of(&r);
        let calls = fetched(people_step(&h, &mut job, vec![]));
        let calls = fetched(people_step(&h, &mut job, calls.iter().map(answer).collect()));
        assert!(calls.iter().any(|c| c.method == "POST"), "{calls:?}");
        role("member");
        let e = failed_with(people_step(&h, &mut job, calls.iter().map(answer).collect()));
        assert_eq!(e.status, 403);
        assert_eq!(fake.ids(), ["101"]);
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["webhook"].as_bool(), v["webhook_cleanup"].as_i64()), (Some(false), Some(2)));
        assert!(v["webhook_error"].as_str().unwrap().contains("stopped partway"), "{v}");
        assert_eq!(people_hook(&h, "pk-100").status, 404);
        assert_eq!(people_hook(&h, "pk-101").status, 404);
        let (_, sent) = drive(&h, cleanup, &answer);
        assert!(sent.iter().any(|c| c.method == "DELETE" && c.url == "https://acme.bamboohr.com/api/v1/webhooks/101"), "{sent:?}");
        assert!(fake.ids().is_empty());
        assert_eq!(records(&h), 0);

        // Saving again, as an admin, adds a webhook again.
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!((v["automatic_webhook"].as_bool(), &v["webhook_error"]), (Some(true), &Value::Null));
    }

    #[test]
    fn hosted_people_sync_signs_in_with_bamboohr_only() {
        let (mut h, admin) = hosted(None);
        with_key(&mut h);
        let fake = FakeBamboo::new(70);
        let answer = |c: &HttpCall| fake.answer(c);

        // BambooHR's terms rule out API keys here, and without the host's BambooHR app there's no
        // other way yet.
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["sign_in_available"].as_bool(), v["api_key_allowed"].as_bool()), (Some(false), Some(false)));
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "k" })), &admin);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (400, Some("api_key_not_allowed")), "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("Sign in with BambooHR"));
        assert_eq!(h.call("POST", "/api/v1/people-sync/sign-in", Some(json!({ "subdomain": "acme" })), &admin).status, 503);
        assert_eq!(h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme" })), &admin).status, 400);

        // With the host's app, BambooHR sends the admin back through the root domain, and the
        // state names the workspace so the root can forward them.
        with_bamboohr_app(&mut h);
        h.cfg.connectors.callback_url = Some("https://kb.test/connect/callback".into());
        let (url, state) = sign_in_link(&h, &admin, "acme");
        assert!(url.contains("&redirect_uri=https%3A%2F%2Fkb.test%2Fsync%2Fbamboohr%2Fcallback&"), "{url}");
        assert!(state.starts_with("acme."), "{state}");
        let (finish, sent) = drive(&h, job_of(&come_back(&h, &admin, &back_with(&state))), &answer);
        assert_eq!(redirected(finish), "https://acme.kb.test/settings/people-sync?people_sync=connected");
        assert!(sent[0].body.as_deref().unwrap().contains("redirect_uri=https%3A%2F%2Fkb.test%2Fsync%2Fbamboohr%2Fcallback"));
        let added: Value =
            serde_json::from_str(sent.iter().find(|c| c.url.ends_with("/webhooks")).unwrap().body.as_deref().unwrap()).unwrap();
        assert_eq!(added["url"], "https://acme.kb.test/hooks/people");
        let v = h.ok("GET", "/api/v1/people-sync", None, &admin);
        assert_eq!((v["auth"].as_str(), v["automatic_webhook"].as_bool()), (Some("oauth"), Some(true)));

        // Still no API keys once signed in; saving again with the sign-in works, and so do syncs.
        let r = h.call("PUT", "/api/v1/people-sync", Some(json!({ "subdomain": "acme", "api_key": "k" })), &admin);
        assert_eq!(r.status, 400);
        let (v, _) = save_people(&h, &admin, json!({ "subdomain": "acme" }), &answer);
        assert_eq!(v["automatic_webhook"], true);
        let r = h.call("POST", "/api/v1/people-sync/run", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert!(sent[0].headers.contains(&bearer("at-1")));
    }

    // -----------------------------------------------------------------------
    // Docs

    /// A fake repository: files by path within the synced folder.
    struct Repo {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    fn sha(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR fake image";

    impl Repo {
        fn new(files: &[(&str, &[u8])]) -> Repo {
            Repo { files: RefCell::new(files.iter().map(|(p, b)| (p.to_string(), b.to_vec())).collect()) }
        }

        fn put(&self, path: &str, bytes: &[u8]) {
            self.files.borrow_mut().insert(path.into(), bytes.to_vec());
        }

        fn remove(&self, path: &str) -> Vec<u8> {
            self.files.borrow_mut().remove(path).unwrap()
        }

        /// GitHub, for `acme/docs` on `main`, folder `handbook`.
        fn github(&self, call: &HttpCall) -> HttpReply {
            let files = self.files.borrow();
            if call.url == "https://api.github.com/repos/acme/docs/git/trees/main%3Ahandbook?recursive=1" {
                let tree: Vec<Value> = files
                    .iter()
                    .map(|(p, b)| json!({ "path": p, "type": "blob", "sha": sha(b), "size": b.len(), "mode": "100644" }))
                    .collect();
                return ok(json!({ "sha": "t", "tree": tree, "truncated": false }));
            }
            if let Some(blob) = call.url.strip_prefix("https://api.github.com/repos/acme/docs/git/blobs/")
                && let Some(b) = files.values().find(|b| sha(b) == blob)
            {
                // GitHub breaks base64 into lines.
                let encoded = base64::engine::general_purpose::STANDARD.encode(b);
                let lines: Vec<String> = encoded.as_bytes().chunks(60).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
                return ok(json!({ "sha": blob, "content": lines.join("\n"), "encoding": "base64", "size": b.len() }));
            }
            HttpReply { status: 404, body: json!({ "message": "Not Found" }).to_string() }
        }
    }

    fn doc_ids(h: &H) -> BTreeMap<String, String> {
        let rows = db_run(h, |db| db.query("SELECT path, target_id FROM docs_items WHERE kind = 'doc'", &[]));
        rows.iter().map(|r| (r.str("path"), r.str("target_id"))).collect()
    }

    fn post(h: &H, id: &str, auth: &Auth) -> Value {
        h.ok("GET", &format!("/api/v1/posts/{id}"), None, auth)
    }

    #[test]
    fn docs_sync_keeps_a_folder_as_posts() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input = json!({ "provider": "github", "repository": "https://github.com/acme/docs", "folder": "/handbook/", "topic_id": topic, "token": "ghp_docs_token" });
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input.clone()), &admin).status, 503, "no connector key");
        with_key(&mut h);
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input.clone()), &mo).status, 403, "admins only");
        assert_eq!(h.call("GET", "/api/v1/docs-sources", None, &mo).status, 403);
        for bad in
            [json!({ "repository": "acme" }), json!({ "folder": "../etc" }), json!({ "branch": "a:b" }), json!({ "provider": "svn" })]
        {
            let mut i = input.clone();
            i.as_object_mut().unwrap().extend(bad.as_object().unwrap().clone());
            assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(i.clone()), &admin).status, 400, "{i}");
        }
        let created = h.ok("POST", "/api/v1/docs-sources", Some(input.clone()), &admin);
        let source = created["source"]["id"].as_str().unwrap().to_string();
        let secret = created["webhook_secret"].as_str().unwrap().to_string();
        assert_eq!(created["source"]["webhook_url"], format!("https://kb.test/hooks/docs/{source}"));
        assert_eq!((created["source"]["repository"].as_str(), created["source"]["folder"].as_str()), (Some("acme/docs"), Some("handbook")));
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input), &admin).status, 409, "the same folder into the same topic");
        // The token and webhook secret are encrypted and never come back.
        let list = h.ok("GET", "/api/v1/docs-sources", None, &admin);
        assert_eq!(list["items"][0]["has_token"], true);
        assert!(!list.to_string().contains("ghp_docs_token") && !list.to_string().contains(&secret), "{list}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources WHERE secret LIKE '%ghp_docs_token%' OR secret LIKE '%whsec_%'"), 0);

        let repo = Repo::new(&[
            (
                "README.md",
                b"# Handbook\n\nStart with [setup](guides/setup.md#install), then [the API](../api/README.md).\n\n![Logo](img/logo.png)\n",
            ),
            ("guides/setup.md", b"---\ntitle: Setting up\n---\n# Setting up\n\nBack [home](../README.md). ![Same logo](../img/logo.png)\n"),
            ("notes.md", b"No heading here; see [missing](later.md).\n"),
            ("img/logo.png", PNG),
            ("img/diagram.svg", b"<svg/>"),
            (".github/ISSUE_TEMPLATE/bug.md", b"# Not docs\n"),
        ]);
        let answer = |c: &HttpCall| repo.github(c);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        let v = filled(finish);
        assert!(sent.iter().all(|c| c.headers.contains(&("authorization".into(), "Bearer ghp_docs_token".into()))));
        assert_eq!((v["files"].as_i64(), v["created"].as_i64(), v["images_uploaded"].as_i64()), (Some(3), Some(3), Some(1)), "{v}");
        assert_eq!((v["done"].as_bool(), v["remaining"].as_i64()), (Some(true), Some(0)));
        let ids = doc_ids(&h);
        assert_eq!(ids.keys().cloned().collect::<Vec<_>>(), vec!["README.md", "guides/setup.md", "notes.md"]);

        // Titles from front matter, a leading heading or the file name; links point at posts, images
        // at the uploaded file, and everything else at GitHub.
        let readme = post(&h, &ids["README.md"], &mo);
        assert_eq!((readme["title"].as_str(), readme["status"].as_str()), (Some("Handbook"), Some("published")));
        let content = readme["content"].as_str().unwrap();
        assert!(!content.starts_with("# Handbook"), "the heading became the title: {content}");
        assert!(content.contains(&format!("[setup](/p/{}#install)", ids["guides/setup.md"])), "{content}");
        assert!(content.contains("[the API](https://github.com/acme/docs/blob/main/api/README.md)"), "{content}");
        let file_id = db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'image'", &[])).unwrap().str("target_id");
        assert!(content.contains(&format!("![Logo](/files/{file_id}/logo.png)")), "{content}");
        assert_eq!(fetch(&h, &format!("/files/{file_id}/logo.png"), &mo).bytes, PNG, "members can see the image");
        let setup = post(&h, &ids["guides/setup.md"], &mo);
        assert_eq!(setup["title"], "Setting up");
        assert!(setup["content"].as_str().unwrap().contains(&format!("/files/{file_id}/logo.png")), "one upload, shown twice");
        assert!(setup["content"].as_str().unwrap().contains(&format!("[home](/p/{})", ids["README.md"])));
        assert_eq!(post(&h, &ids["notes.md"], &mo)["title"], "Notes");
        // Sub-folders are sub-topics; posts are in the source's topic too.
        let names: Vec<&str> = setup["topics"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["Guides", "Handbook"]);
        assert_eq!(readme["synced_from"]["url"], "https://github.com/acme/docs/blob/main/handbook/README.md");
        assert_eq!(readme["synced_from"]["path"], "handbook/README.md");
        assert_eq!(readme["backlinks"][0]["id"].as_str(), Some(ids["guides/setup.md"].as_str()));
        // Nobody was notified: the text was written elsewhere.
        assert_eq!(count(&h, "SELECT COUNT(*) FROM notifications"), 0);

        // Synced posts are read-only here; status, verification and topics still work.
        let readme_id = ids["README.md"].clone();
        let r = h.call("PATCH", &format!("/api/v1/posts/{readme_id}"), Some(json!({ "content": "local edit" })), &mo);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (409, Some("synced_post")), "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("Edit it there"));
        let r = h.call(
            "POST",
            &format!("/api/v1/posts/{readme_id}/edit"),
            Some(json!({ "edits": [{ "type": "append", "content": "x" }] })),
            &admin,
        );
        assert_eq!(r.status, 409);
        assert_eq!(
            h.call("POST", &format!("/api/v1/posts/{readme_id}/versions/1/restore"), None, &admin).status,
            200,
            "a no-op restore is fine"
        );
        h.ok("POST", &format!("/api/v1/posts/{readme_id}/verify"), Some(json!({})), &mo);

        // Webhooks: GitHub signs the body with the source's secret.
        let push = json!({ "ref": "refs/heads/main", "after": "abc" }).to_string();
        let sign = |body: &str| format!("sha256={}", hmac_sha256_hex(&secret, body));
        let path = format!("/hooks/docs/{source}");
        assert_eq!(hook(&h, &path, &push, &[("x-github-event", "push"), ("x-hub-signature-256", "sha256=00")]).status, 401);
        assert_eq!(hook(&h, &path, &push, &[("x-github-event", "push")]).status, 401, "unsigned");
        assert_eq!(hook(&h, "/hooks/docs/nope", &push, &[("x-github-event", "push"), ("x-hub-signature-256", &sign(&push))]).status, 404);
        let r = hook(&h, &path, "{}", &[("x-github-event", "ping"), ("x-hub-signature-256", &sign("{}"))]);
        assert_eq!(r.body["status"], "pong");
        let other = json!({ "ref": "refs/heads/feature" }).to_string();
        let r = hook(&h, &path, &other, &[("x-github-event", "push"), ("x-hub-signature-256", &sign(&other))]);
        assert_eq!((r.body["status"].as_str(), r.effects.len()), (Some("ignored"), 0), "another branch");

        // Upstream: setup changes, notes moves without changes, the README goes, an image is added.
        repo.put("guides/setup.md", b"# Setting up\n\nNew steps. ![Same logo](../img/logo.png)\n");
        let notes = repo.remove("notes.md");
        repo.put("archive/old-notes.md", &notes);
        let readme_md = repo.remove("README.md");
        let r = hook(&h, &path, &push, &[("x-github-event", "push"), ("x-hub-signature-256", &sign(&push))]);
        assert_eq!(r.status, 200, "{}", r.body);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(
            (v["updated"].as_i64(), v["renamed"].as_i64(), v["archived"].as_i64(), v["created"].as_i64()),
            (Some(2), Some(1), Some(1), Some(0)),
            "the moved file is synced again at its new path: {v}"
        );
        assert_eq!((v["images_uploaded"].as_i64(), v["images_reused"].as_i64()), (Some(0), Some(1)), "{v}");
        let ids2 = doc_ids(&h);
        assert_eq!(ids2["archive/old-notes.md"], ids["notes.md"], "a rename keeps the post");
        let setup = post(&h, &ids["guides/setup.md"], &admin);
        assert!(setup["content"].as_str().unwrap().contains("New steps."));
        let versions = h.ok("GET", &format!("/api/v1/posts/{}/versions", ids["guides/setup.md"]), None, &admin);
        assert_eq!(versions["current_version"], 2, "each change is a version");
        assert!(versions["items"][0]["note"].as_str().unwrap().contains("Synced from GitHub"));
        let readme = post(&h, &readme_id, &admin);
        assert_eq!((readme["status"].as_str(), readme["synced_from"]["removed"].as_bool()), (Some("archived"), Some(true)));
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM posts WHERE id = '{readme_id}'")), 1, "never deleted");
        let notes_post = post(&h, &ids["notes.md"], &admin);
        let names: Vec<&str> = notes_post["topics"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["Archive", "Handbook"], "moved to its new folder's topic");

        // The README comes back: its post is published again. Unchanged files aren't read.
        repo.put("README.md", &readme_md);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        let v = filled(finish);
        assert_eq!((v["restored"].as_i64(), v["unchanged"].as_i64()), (Some(1), Some(3)), "its text hadn't changed: {v}");
        assert_eq!(sent.iter().filter(|c| c.url.contains("/git/blobs/")).count(), 1, "only the README was read");
        assert_eq!(post(&h, &readme_id, &admin)["status"], "published");

        // A post erased here comes back at the next sync, with its id.
        let notes_id = ids["notes.md"].clone();
        h.ok("DELETE", &format!("/api/v1/posts/{notes_id}?permanent=true"), None, &admin);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(v["created"], 1, "{v}");
        assert_eq!(post(&h, &notes_id, &admin)["title"], "Old notes");

        // A large first sync carries on where the last left off; links to files not synced yet
        // already point at their posts.
        for i in 0..23 {
            repo.put(&format!("many/doc-{i:02}.md"), format!("# Doc {i}\n\nNext: [next](doc-{:02}.md)\n", i + 1).as_bytes());
        }
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((v["created"].as_i64(), v["remaining"].as_i64(), v["done"].as_bool()), (Some(20), Some(3), Some(false)), "{v}");
        assert_eq!(h.ok("GET", "/api/v1/docs-sources", None, &admin)["items"][0]["last_status"], "partial");
        let ids3 = doc_ids(&h);
        let doc0 = post(&h, &ids3["many/doc-00.md"], &admin);
        assert!(doc0["content"].as_str().unwrap().contains(&format!("/p/{}", ids3["many/doc-01.md"])));
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((v["created"].as_i64(), v["remaining"].as_i64(), v["done"].as_bool()), (Some(3), Some(0), Some(true)), "{v}");

        // Text that names uploads never attaches them: not the admin's own unattached upload (the
        // sync writes as them), and not a file in a private post.
        let mine = upload(&h, &admin, "secret.png", None, PNG, None).body["id"].as_str().unwrap().to_string();
        let vault = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Vault", "visibility": "private" })), &admin)["id"].clone();
        let hidden = h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Hidden", "topic_ids": [vault], "status": "published" })), &admin);
        let hidden_file = upload(&h, &admin, "plan.png", None, PNG, hidden["id"].as_str()).body["id"].as_str().unwrap().to_string();
        let leak = format!("# Leak\n\n![a](https://kb.test/files/{mine}/secret.png) ![b](https://kb.test/files/{hidden_file}/plan.png)\n");
        repo.put("leak.md", leak.as_bytes());
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        assert_eq!(filled(drive(&h, job_of(&r), &answer).0)["created"], 1);
        let leaked = post(&h, &doc_ids(&h)["leak.md"], &mo);
        assert!(leaked["content"].as_str().unwrap().contains(&mine), "the text is kept as written");
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM files WHERE id = '{mine}' AND post_id IS NULL")), 1, "still unattached");
        assert_eq!(fetch(&h, &format!("/files/{mine}/secret.png"), &mo).status, 404);
        assert_eq!(fetch(&h, &format!("/files/{hidden_file}/plan.png"), &mo).status, 404);

        // A file with more images than one run uploads waits; its images, stored meanwhile, join
        // its post once it's written.
        let mut gallery = String::from("# Gallery\n\n");
        for i in 0..11 {
            let mut png = PNG.to_vec();
            png.push(i as u8);
            repo.put(&format!("gallery/{i:02}.png"), &png);
            gallery.push_str(&format!("![{i}](gallery/{i:02}.png)\n"));
        }
        repo.put("gallery.md", gallery.as_bytes());
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((v["created"].as_i64(), v["images_uploaded"].as_i64(), v["remaining"].as_i64()), (Some(0), Some(10), Some(1)), "{v}");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(
            (v["created"].as_i64(), v["images_uploaded"].as_i64(), v["images_reused"].as_i64()),
            (Some(1), Some(1), Some(10)),
            "{v}"
        );
        let gallery_id = doc_ids(&h)["gallery.md"].clone();
        assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM files WHERE post_id = '{gallery_id}'")), 11);
        let first = db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'image' AND path = 'gallery/00.png'", &[]))
            .unwrap()
            .str("target_id");
        assert_eq!(fetch(&h, &format!("/files/{first}/00.png"), &mo).status, 200, "readers of the post see its images");

        // A file that comes back is published again once it's written, however many runs that
        // takes: here its 11 images changed, more than one run uploads.
        let gallery_md = repo.remove("gallery.md");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        assert_eq!(filled(drive(&h, job_of(&r), &answer).0)["archived"], 1);
        for i in 0..11 {
            let mut png = PNG.to_vec();
            png.extend([i as u8, 0xFF]);
            repo.put(&format!("gallery/{i:02}.png"), &png);
        }
        repo.put("gallery.md", &gallery_md);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((v["images_uploaded"].as_i64(), v["restored"].as_i64(), v["done"].as_bool()), (Some(10), Some(0), Some(false)), "{v}");
        let waiting = post(&h, &gallery_id, &admin);
        assert_eq!((waiting["status"].as_str(), waiting["synced_from"]["removed"].as_bool()), (Some("archived"), Some(true)));
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let v = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((v["images_uploaded"].as_i64(), v["restored"].as_i64(), v["done"].as_bool()), (Some(1), Some(1), Some(true)), "{v}");
        let back = post(&h, &gallery_id, &mo);
        assert_eq!((back["status"].as_str(), back["synced_from"]["removed"].as_bool()), (Some("published"), Some(false)));

        // A folder that comes back empty (renamed, or a bad branch) archives nothing.
        let r = h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "branch": "gone" })), &admin);
        assert_eq!(r.status, 200);
        assert!(r.body["webhook_secret"].is_null(), "secrets only when asked for");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &|_| ok(json!({ "tree": [], "truncated": false })));
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("nothing was archived")), "{finish:?}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM posts WHERE status = 'archived'"), 0);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &answer);
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("no branch `gone`")), "{finish:?}");
        assert_eq!(h.ok("GET", "/api/v1/docs-sources", None, &admin)["items"][0]["last_status"], "failed");

        // A new webhook secret replaces the old one.
        let rotated =
            h.ok("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "branch": "main", "new_webhook_secret": true })), &admin);
        let new_secret = rotated["webhook_secret"].as_str().unwrap();
        assert_ne!(new_secret, secret);
        assert_eq!(hook(&h, &path, &push, &[("x-github-event", "push"), ("x-hub-signature-256", &sign(&push))]).status, 401);

        // Removing the source leaves its posts, now editable here.
        h.ok("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_items"), 0);
        let edited = h.ok("PATCH", &format!("/api/v1/posts/{readme_id}"), Some(json!({ "content": "local edit" })), &mo);
        assert!(edited["synced_from"].is_null());
        assert_eq!(edited["content"], "local edit");
    }

    /// GitLab, for the project `ops/runbooks` on `trunk` at git.acme.test: files by path. Files in
    /// `too_large` answer the way a blob cut short at the size limit does.
    struct Lab {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        too_large: RefCell<Vec<String>>,
    }

    impl Lab {
        fn new(files: &[(&str, &[u8])]) -> Lab {
            Lab { files: RefCell::new(files.iter().map(|(p, b)| (p.to_string(), b.to_vec())).collect()), too_large: RefCell::new(vec![]) }
        }

        fn put(&self, path: &str, bytes: &[u8]) {
            self.files.borrow_mut().insert(path.into(), bytes.to_vec());
        }

        fn answer(&self, c: &HttpCall) -> HttpReply {
            let base = "https://git.acme.test/api/v4/projects/ops%2Frunbooks/repository";
            let files = self.files.borrow();
            if let Some(page) = c.url.strip_prefix(&format!("{base}/tree?ref=trunk&recursive=true&per_page=100&page=")) {
                let page: usize = page.split('&').next().unwrap().parse().unwrap();
                let entries: Vec<Value> = files
                    .iter()
                    .map(|(p, b)| json!({ "id": sha(b), "name": p.rsplit('/').next(), "type": "blob", "path": p, "mode": "100644" }))
                    .collect();
                return ok(json!(entries.chunks(100).nth(page - 1).map(<[Value]>::to_vec).unwrap_or_default()));
            }
            if let Some(blob) = c.url.strip_prefix(&format!("{base}/blobs/"))
                && let Some((path, b)) = files.iter().find(|(_, b)| sha(b) == blob)
            {
                if self.too_large.borrow().contains(path) {
                    return HttpReply { status: 200, body: "{\"content\": \"aGVsbG8".into() };
                }
                return ok(json!({ "content": base64::engine::general_purpose::STANDARD.encode(b), "encoding": "base64" }));
            }
            HttpReply { status: 404, body: "{}".into() }
        }
    }

    /// One step of a job, in its own transaction.
    fn step_once(h: &H, job: &mut Job, replies: Vec<HttpReply>) -> Step {
        h.store
            .with_tx(|db| {
                let (step, _) = connect::guarded_step(db, &h.cfg, job, replies, chrono::Utc::now(), |_| None);
                let ok = step.is_ok();
                (step, ok)
            })
            .unwrap()
            .unwrap()
    }

    fn gitlab_source(h: &H, admin: &Auth, topic: &str) -> (String, String) {
        let input = json!({ "provider": "gitlab", "repository": "https://git.acme.test/ops/runbooks", "topic_id": topic, "token": "glpat-secret", "branch": "trunk" });
        let created = h.ok("POST", "/api/v1/docs-sources", Some(input), admin);
        assert_eq!(created["source"]["host"], "git.acme.test");
        (created["source"]["id"].as_str().unwrap().to_string(), created["webhook_secret"].as_str().unwrap().to_string())
    }

    #[test]
    fn docs_sync_from_gitlab() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let (mo_id, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let (zed_id, zed) = h.user(&admin, "zed@acme.test", "Zed", "member");
        let ops = json!({ "name": "Ops", "visibility": "private", "members": [mo_id] });
        let topic = h.ok("POST", "/api/v1/topics", Some(ops), &admin)["id"].as_str().unwrap().to_string();
        let (source, secret) = gitlab_source(&h, &admin, &topic);
        let lab =
            Lab::new(&[("paging.md", b"# Paging\n\nSee [deploys](deploys/rollback.md).\n"), ("deploys/rollback.md", b"# Rollback\n")]);
        let answer = |c: &HttpCall| lab.answer(c);
        // GitLab sends the secret token itself.
        let push = json!({ "ref": "refs/heads/trunk", "object_kind": "push" }).to_string();
        let path = format!("/hooks/docs/{source}");
        assert_eq!(hook(&h, &path, &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", "wrong")]).status, 401);
        let r = hook(&h, &path, &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", &secret)]);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        let v = filled(finish);
        assert_eq!(v["created"], 2, "{v}");
        assert_eq!(sent.iter().filter(|c| c.url.contains("/tree?")).count(), 10, "pages asked for at once");
        assert!(sent.iter().all(|c| c.headers.contains(&("authorization".into(), "Bearer glpat-secret".into()))));
        let ids = doc_ids(&h);
        let paging = post(&h, &ids["paging.md"], &admin);
        assert!(paging["content"].as_str().unwrap().contains(&format!("/p/{}", ids["deploys/rollback.md"])));
        assert_eq!(paging["synced_from"]["url"], "https://git.acme.test/ops/runbooks/-/blob/trunk/paging.md");
        // A private topic's sync makes private sub-topics with its members, so posts stay as
        // private as the topic.
        let rollback_id = ids["deploys/rollback.md"].clone();
        let topic_names = |h: &H| -> Vec<String> {
            post(h, &rollback_id, &admin)["topics"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
        };
        assert_eq!(topic_names(&h), vec!["Deploys", "Ops"]);
        let deploys = db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'folder' AND path = 'deploys'", &[]))
            .unwrap()
            .str("target_id");
        let sub = h.ok("GET", &format!("/api/v1/topics/{deploys}"), None, &admin);
        assert_eq!(sub["visibility"], "private");
        assert!(sub["members"].as_array().unwrap().iter().any(|m| m["id"] == mo_id.as_str()), "{sub}");
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback_id}"), None, &mo).status, 200);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback_id}"), None, &zed).status, 404);

        // Someone makes the sub-topic public: the next sync takes the source's posts out of it and
        // skips its files, and leaves its visibility alone.
        let sync = |h: &H| -> Value {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            filled(drive(h, job_of(&r), &answer).0)
        };
        let set_visibility = |v: &str| h.ok("PATCH", &format!("/api/v1/topics/{deploys}"), Some(json!({ "visibility": v })), &admin);
        set_visibility("org");
        let v = sync(&h);
        assert_eq!(v["skipped"][0]["path"], "deploys/rollback.md", "{v}");
        assert!(v["skipped"][0]["reason"].as_str().unwrap().contains("Deploys"), "{v}");
        assert_eq!(topic_names(&h), vec!["Ops"]);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback_id}"), None, &zed).status, 404);
        assert_eq!(h.ok("GET", &format!("/api/v1/topics/{deploys}"), None, &admin)["visibility"], "org");
        // Private again, but with a member the source's topic doesn't have: still skipped.
        set_visibility("private");
        h.ok("POST", &format!("/api/v1/topics/{deploys}/members"), Some(json!({ "user": zed_id })), &admin);
        let v = sync(&h);
        assert_eq!(v["skipped"][0]["path"], "deploys/rollback.md", "{v}");
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback_id}"), None, &zed).status, 404);
        // Fixed: the post goes back in.
        h.ok("DELETE", &format!("/api/v1/topics/{deploys}/members/{zed_id}"), None, &admin);
        let v = sync(&h);
        assert_eq!(v["skipped"], json!([]), "{v}");
        assert_eq!(topic_names(&h), vec!["Deploys", "Ops"]);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{}", ids["paging.md"]), None, &zed).status, 404);

        // A synced post stays in its source's topic...
        let r = h.call("PATCH", &format!("/api/v1/posts/{rollback_id}"), Some(json!({ "remove_topic_ids": [topic] })), &admin);
        assert_eq!(r.status, 409, "{}", r.body);
        // ...and one that left it anyway, so that only the sub-topic holds it, isn't left in no
        // topic (visible to everyone) when the sub-topic is made public: the sync puts it back in
        // the source's topic first.
        db_run(&h, |db| db.execute(&format!("DELETE FROM post_topics WHERE post_id = '{rollback_id}' AND topic_id = '{topic}'"), &[]));
        set_visibility("org");
        sync(&h);
        assert_eq!(topic_names(&h), vec!["Ops"]);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback_id}"), None, &zed).status, 404);
        set_visibility("private");
        sync(&h);
        assert_eq!(topic_names(&h), vec!["Deploys", "Ops"]);

        // A sub-topic made public while a sync is fetching files gets nothing new: the step that
        // writes checks again.
        lab.put("deploys/rollback.md", b"# Rollback\n\nThe private steps.\n");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let mut job = job_of(&r);
        let tree = match step_once(&h, &mut job, vec![]) {
            Step::Fetch(calls) => calls.iter().map(&answer).collect(),
            other => panic!("{other:?}"),
        };
        let blobs = match step_once(&h, &mut job, tree) {
            Step::Fetch(calls) => calls.iter().map(&answer).collect(),
            other => panic!("{other:?}"),
        };
        set_visibility("org");
        let v = match step_once(&h, &mut job, blobs) {
            Step::Done(f) => filled(f),
            other => panic!("{other:?}"),
        };
        assert_eq!(v["skipped"][0]["path"], "deploys/rollback.md", "{v}");
        let rollback = post(&h, &rollback_id, &admin);
        assert!(!rollback["content"].as_str().unwrap().contains("private steps"), "not written");
        assert_eq!(topic_names(&h), vec!["Ops"]);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback_id}"), None, &zed).status, 404);
        // Fixed, it's written at the next sync.
        set_visibility("private");
        let v = sync(&h);
        assert_eq!(v["updated"], 1, "{v}");
        assert!(post(&h, &rollback_id, &mo)["content"].as_str().unwrap().contains("private steps"));
    }

    #[test]
    fn docs_sync_writes_only_as_an_admin() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let ada_id = h.ok("GET", "/api/v1/me", None, &admin)["user"]["id"].as_str().unwrap().to_string();
        let (mo_id, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let (ann_id, _) = h.user(&admin, "ann@acme.test", "Ann", "admin");
        let ann_admin =
            h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "ann", "user": ann_id, "scopes": ["read", "write", "admin"] })), &admin);
        let ann_admin = Auth::Bearer(ann_admin["token"].as_str().unwrap().to_string());
        let ann = sign_in(&h, "ann@acme.test", "password123");
        let ops = json!({ "name": "Ops", "visibility": "private", "members": [mo_id] });
        let topic = h.ok("POST", "/api/v1/topics", Some(ops), &admin)["id"].as_str().unwrap().to_string();
        // Ann, an admin, sets the source up; its posts are first written as her.
        let (source, _) = gitlab_source(&h, &ann_admin, &topic);
        let lab = Lab::new(&[("paging.md", b"# Paging\n")]);
        let answer = |c: &HttpCall| lab.answer(c);
        let sync = || -> Value {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            filled(drive(&h, job_of(&r), &answer).0)
        };
        sync();
        let paging_id = doc_ids(&h)["paging.md"].clone();
        assert_eq!(post(&h, &paging_id, &admin)["author"]["id"].as_str(), Some(ann_id.as_str()));

        // Ann stops being an admin: she can't see the topic, and syncs no longer write as her.
        h.ok("PATCH", &format!("/api/v1/users/{ann_id}"), Some(json!({ "role": "member" })), &admin);
        assert_eq!(h.call("GET", &format!("/api/v1/topics/{topic}"), None, &ann).status, 404);
        lab.put("paging.md", b"# Paging\n\nThe new private rota.\n");
        lab.put("deploys/rollback.md", b"# Rollback\n\nPrivate steps.\n");
        let v = sync();
        assert_eq!((v["created"].as_i64(), v["updated"].as_i64()), (Some(1), Some(1)), "{v}");
        let ids = doc_ids(&h);
        for id in [&ids["paging.md"], &ids["deploys/rollback.md"]] {
            assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &ann).status, 404, "Ann can't read new synced content");
            assert_eq!(post(&h, id, &admin)["author"]["id"].as_str(), Some(ada_id.as_str()), "written as an active admin");
            assert_eq!(h.call("GET", &format!("/api/v1/posts/{id}"), None, &mo).status, 200);
        }
        let deploys = db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'folder' AND path = 'deploys'", &[]))
            .unwrap()
            .str("target_id");
        assert_eq!(h.call("GET", &format!("/api/v1/topics/{deploys}"), None, &ann).status, 404);
        let members = h.ok("GET", &format!("/api/v1/topics/{deploys}"), None, &admin)["members"].clone();
        assert!(members.as_array().unwrap().iter().all(|m| m["id"] != ann_id.as_str()), "{members}");
    }

    #[test]
    fn docs_sync_survives_long_folder_names_and_long_rewrites() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Runbooks" })), &admin)["id"].as_str().unwrap().to_string();
        let (source, _) = gitlab_source(&h, &admin, &topic);
        // Two folders with 121-character names that share their first 120 characters.
        let long_a = format!("{}a", "x".repeat(120));
        let long_b = format!("{}b", "x".repeat(120));
        // 780 KB of links to a missing file: allowed as Markdown, but longer than a post once each
        // link points at GitLab.
        let links = "[x](missing) ".repeat(60_000);
        let lab = Lab::new(&[]);
        lab.put(&format!("{long_a}/one.md"), b"# One\n");
        lab.put(&format!("{long_b}/two.md"), b"# Two\n");
        lab.put("links.md", format!("# Links\n\n{links}\n").as_bytes());
        lab.put("ok.md", b"# Fine\n");
        let answer = |c: &HttpCall| lab.answer(c);
        let sync = || -> (Value, usize) {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            let (finish, sent) = drive(&h, job_of(&r), &answer);
            (filled(finish), sent.iter().filter(|c| c.url.contains("/blobs/")).count())
        };
        let (v, _) = sync();
        assert_eq!(v["created"], 3, "the rest of the batch goes on: {v}");
        assert_eq!(v["skipped"][0]["path"], "links.md", "{v}");
        assert!(v["skipped"][0]["reason"].as_str().unwrap().contains("2 MB"), "{v}");
        let folders = db_run(&h, |db| db.query("SELECT path, target_id FROM docs_items WHERE kind = 'folder' ORDER BY path", &[]));
        assert_eq!(
            folders.iter().map(|r| r.str("path")).collect::<Vec<_>>(),
            vec![long_a.clone(), long_b.clone()],
            "full paths are the keys"
        );
        let names: Vec<String> = folders
            .iter()
            .map(|r| h.ok("GET", &format!("/api/v1/topics/{}", r.str("target_id")), None, &admin)["name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.iter().all(|n| n.chars().count() <= 120), "{names:?}");
        assert_ne!(names[0], names[1], "unique among siblings");
        assert!(names[1].ends_with(" (2)"), "{names:?}");
        // The long file isn't read again until it changes.
        let (v, read) = sync();
        assert_eq!((read, v["skipped"][0]["path"].as_str()), (0, Some("links.md")), "{v}");
    }

    #[test]
    fn docs_sync_sends_workspace_webhooks() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.example.com/dumbslab", "events": ["post.*"] })), &admin);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Runbooks" })), &admin)["id"].as_str().unwrap().to_string();
        let (source, _) = gitlab_source(&h, &admin, &topic);
        let lab = Lab::new(&[("a.md", b"# A\n"), ("b.md", b"# B\n")]);
        // Like a host: drive the job, then take what it left to deliver.
        let run = || -> Vec<String> {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            let mut job = job_of(&r);
            let mut replies = vec![];
            loop {
                match step_once(&h, &mut job, replies) {
                    Step::Fetch(calls) => replies = calls.iter().map(|c| lab.answer(c)).collect(),
                    Step::Done(f) => {
                        filled(f);
                        break;
                    }
                }
            }
            job.take_effects()
                .iter()
                .filter_map(|e| match e {
                    Effect::Webhook(d) => d.headers.iter().find(|(k, _)| k == "x-dumbslab-event").map(|(_, v)| v.clone()),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(run(), vec!["post.created", "post.created"]);
        lab.put("a.md", b"# A\n\nChanged.\n");
        lab.files.borrow_mut().remove("b.md");
        let mut events = run();
        events.sort();
        assert_eq!(events, vec!["post.archived", "post.updated"]);
        assert!(run().is_empty(), "nothing changed, nothing sent");
    }

    /// Runs a job to the end like a host (each step through `guarded_step`), and returns its result
    /// and what it left to deliver.
    fn run_to_end(h: &H, mut job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (Value, Vec<Effect>) {
        let mut replies = vec![];
        loop {
            match step_once(h, &mut job, replies) {
                Step::Fetch(calls) => replies = calls.iter().map(answer).collect(),
                Step::Done(f) => return (filled(f), job.take_effects()),
            }
        }
    }

    /// The workspace webhook events among a job's effects.
    fn events(effects: &[Effect]) -> Vec<String> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Webhook(d) if !d.webhook_id.starts_with("slack:") => {
                    d.headers.iter().find(|(k, _)| k == "x-dumbslab-event").map(|(_, v)| v.clone())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn docs_sync_announces_posts_by_their_final_topics() {
        let (h, admin) = super::slack::connected();
        h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0ALLPOSTS", "updated_posts": true })), &admin);
        let ops = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Ops", "visibility": "private" })), &admin)["id"]
            .as_str()
            .unwrap()
            .to_string();
        let handbook = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let lab = Lab::new(&[("rota.md", b"# Confidential rota\n\nWho is on call.\n"), ("deploys/rollback.md", b"# Secret rollback\n")]);
        let answer = |c: &HttpCall| lab.answer(c);
        // A private topic's synced posts go to no channel for every post: they're in the private
        // topic by the time anything hears of them.
        let (private_source, _) = gitlab_source(&h, &admin, &ops);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{private_source}/sync"), None, &admin);
        let (v, effects) = run_to_end(&h, job_of(&r), &answer);
        assert_eq!(v["created"], 2, "{v}");
        let messages = super::slack::slack_messages(&effects);
        assert!(messages.is_empty(), "{messages:?}");
        // The same files in an org-wide topic are announced.
        let (public_source, _) = gitlab_source(&h, &admin, &handbook);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{public_source}/sync"), None, &admin);
        let (_, effects) = run_to_end(&h, job_of(&r), &answer);
        let messages = super::slack::slack_messages(&effects);
        assert_eq!(messages.len(), 2, "one per post: {messages:?}");
        assert!(messages.iter().all(|m| m["channel"] == "C0ALLPOSTS"));
        assert!(messages.iter().any(|m| m.to_string().contains("Confidential rota")));
        // Updates too: a change to the private copy stays out of the channel.
        lab.put("rota.md", b"# Confidential rota\n\nWho is on call now.\n");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{private_source}/sync"), None, &admin);
        let (v, effects) = run_to_end(&h, job_of(&r), &answer);
        assert_eq!(v["updated"], 1, "{v}");
        assert!(super::slack::slack_messages(&effects).is_empty());
        assert_eq!(events(&effects), Vec::<String>::new(), "no workspace webhooks are set up");
    }

    #[test]
    fn docs_sync_records_moves_between_folders() {
        let (h, admin) = super::slack::connected();
        h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0ALLPOSTS", "updated_posts": true })), &admin);
        h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.example.com/dumbslab", "events": ["post.*"] })), &admin);
        for (name, visibility) in [("Handbook", "org"), ("Ops", "private")] {
            let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": name, "visibility": visibility })), &admin)["id"]
                .as_str()
                .unwrap()
                .to_string();
            let (source, _) = gitlab_source(&h, &admin, &topic);
            let guide: &[u8] = b"# Guide\n\nThe same words.\n";
            let lab = Lab::new(&[("a/guide.md", guide)]);
            let answer = |c: &HttpCall| lab.answer(c);
            let sync = || {
                let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
                run_to_end(&h, job_of(&r), &answer)
            };
            let (_, effects) = sync();
            let announced = super::slack::slack_messages(&effects).len();
            assert_eq!(announced, usize::from(visibility == "org"), "{name}: only an org-wide post is announced");
            let post_id =
                db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'doc' AND source_id = ?", &[source.as_str().into()]))
                    .unwrap()
                    .str("target_id");
            let folder = |path: &str| {
                db_run(&h, |db| {
                    db.one(
                        "SELECT target_id FROM docs_items WHERE kind = 'folder' AND source_id = ? AND path = ?",
                        &[source.as_str().into(), path.into()],
                    )
                })
                .map(|r| r.str("target_id"))
            };

            // The file moves to another folder, its title and text unchanged.
            lab.files.borrow_mut().remove("a/guide.md");
            lab.put("b/guide.md", guide);
            let (v, effects) = sync();
            assert_eq!((v["renamed"].as_i64(), v["unchanged"].as_i64()), (Some(1), Some(1)), "{name}: {v}");
            assert_eq!(events(&effects), vec!["post.moved"], "{name}: one event, like any change of topics");
            let payload: Value = effects
                .iter()
                .find_map(|e| match e {
                    Effect::Webhook(d) if !d.webhook_id.starts_with("slack:") => serde_json::from_str(&d.body).ok(),
                    _ => None,
                })
                .unwrap();
            assert_eq!(payload["post_id"].as_str(), Some(post_id.as_str()));
            assert_eq!(payload["data"]["added"], json!([folder("b").unwrap()]), "{name}: {payload}");
            assert_eq!(payload["data"]["removed"], json!([folder("a").unwrap()]), "{name}: {payload}");
            let recorded = format!("SELECT COUNT(*) FROM activity WHERE event = 'post.moved' AND post_id = '{post_id}'");
            assert_eq!(count(&h, &recorded), 1, "{name}: in the activity log");
            // Moves aren't announced in Slack, so nothing private reaches a channel for every post.
            assert!(super::slack::slack_messages(&effects).is_empty(), "{name}");
            // Nothing more to record when nothing changes.
            assert!(events(&sync().1).is_empty(), "{name}");
        }
    }

    #[test]
    fn docs_sync_records_privacy_repairs() {
        let (h, admin) = super::slack::connected();
        h.ok("POST", "/api/v1/slack/channels", Some(json!({ "channel": "C0ALLPOSTS", "updated_posts": true })), &admin);
        h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.example.com/dumbslab", "events": ["post.*"] })), &admin);
        let (mo_id, _) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let ops = json!({ "name": "Ops", "visibility": "private", "members": [mo_id] });
        let ops = h.ok("POST", "/api/v1/topics", Some(ops), &admin)["id"].as_str().unwrap().to_string();
        let (source, _) = gitlab_source(&h, &admin, &ops);
        let lab = Lab::new(&[("deploys/rollback.md", b"# Rollback\n"), ("deploys/restart.md", b"# Restart\n")]);
        let answer = |c: &HttpCall| lab.answer(c);
        let sync = || {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            run_to_end(&h, job_of(&r), &answer)
        };
        assert_eq!(sync().0["created"], 2);
        let ids = doc_ids(&h);
        let (rollback, restart) = (ids["deploys/rollback.md"].clone(), ids["deploys/restart.md"].clone());
        let deploys = db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'folder' AND path = 'deploys'", &[]))
            .unwrap()
            .str("target_id");

        // No file changes, but the folder's topic is made public, and one post had been taken out
        // of Ops (S1's case). The repair is the run's only change, and it's recorded per post.
        db_run(&h, |db| db.execute(&format!("DELETE FROM post_topics WHERE post_id = '{restart}' AND topic_id = '{ops}'"), &[]));
        h.ok("PATCH", &format!("/api/v1/topics/{deploys}"), Some(json!({ "visibility": "org" })), &admin);
        let (v, effects) = sync();
        assert_eq!((v["created"].as_i64(), v["updated"].as_i64()), (Some(0), Some(0)), "{v}");
        assert_eq!(events(&effects), vec!["post.moved", "post.moved"]);
        let moves: BTreeMap<String, Value> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Webhook(d) if !d.webhook_id.starts_with("slack:") => serde_json::from_str::<Value>(&d.body).ok(),
                _ => None,
            })
            .map(|p| (p["post_id"].as_str().unwrap().to_string(), p["data"].clone()))
            .collect();
        assert_eq!((&moves[&rollback]["added"], &moves[&rollback]["removed"]), (&json!([]), &json!([deploys])), "{moves:?}");
        assert_eq!((&moves[&restart]["added"], &moves[&restart]["removed"]), (&json!([ops]), &json!([deploys])), "{moves:?}");
        for id in [&rollback, &restart] {
            assert_eq!(count(&h, &format!("SELECT COUNT(*) FROM activity WHERE event = 'post.moved' AND post_id = '{id}'")), 1);
        }
        assert!(super::slack::slack_messages(&effects).is_empty(), "moves aren't announced");
        // Repaired already: the next sync records nothing.
        let (_, effects) = sync();
        assert!(events(&effects).is_empty(), "{:?}", events(&effects));
    }

    #[test]
    fn docs_sync_takes_back_only_its_own_grants() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let (mo_id, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let (ann_id, _) = h.user(&admin, "ann@acme.test", "Ann", "admin");
        let ann_admin =
            h.ok("POST", "/api/v1/tokens", Some(json!({ "name": "ann", "user": ann_id, "scopes": ["read", "write", "admin"] })), &admin);
        let ann_admin = Auth::Bearer(ann_admin["token"].as_str().unwrap().to_string());
        let ann = sign_in(&h, "ann@acme.test", "password123");
        let ops = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Ops", "visibility": "private", "members": [mo_id] })), &admin)["id"]
            .as_str()
            .unwrap()
            .to_string();
        let (source, _) = gitlab_source(&h, &ann_admin, &ops);
        let lab = Lab::new(&[("deploys/rollback.md", b"# Rollback\n")]);
        let answer = |c: &HttpCall| lab.answer(c);
        let sync = || {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            filled(drive(&h, job_of(&r), &answer).0)
        };
        sync();
        let deploys = db_run(&h, |db| db.one("SELECT target_id FROM docs_items WHERE kind = 'folder' AND path = 'deploys'", &[]))
            .unwrap()
            .str("target_id");
        let rollback = doc_ids(&h)["deploys/rollback.md"].clone();
        let members = |h: &H| -> Vec<String> {
            let t = h.ok("GET", &format!("/api/v1/topics/{deploys}"), None, &admin);
            t["members"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap().to_string()).collect()
        };
        assert!(!members(&h).contains(&ann_id), "Ann made the topic but isn't in Ops");
        assert!(members(&h).contains(&mo_id));

        // An admin gives Ann a place in the folder's topic on purpose, with a post that has
        // nothing to do with the sync. Then Ann is demoted, and the sync runs.
        h.ok("POST", &format!("/api/v1/topics/{deploys}/members"), Some(json!({ "user": ann_id })), &admin);
        let notes =
            h.ok("POST", "/api/v1/posts", Some(json!({ "title": "Ann's notes", "status": "published", "topic_ids": [deploys] })), &admin);
        let notes = notes["id"].as_str().unwrap().to_string();
        h.ok("PATCH", &format!("/api/v1/users/{ann_id}"), Some(json!({ "role": "member" })), &admin);
        let v = sync();
        // That membership was someone's choice: it stays, and so does Ann's access to the post.
        assert!(members(&h).contains(&ann_id), "an explicit membership stays");
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{notes}"), None, &ann).status, 200);
        // But it lets in someone Ops doesn't, so the synced post leaves the topic.
        assert_eq!(v["skipped"][0]["path"], "deploys/rollback.md", "{v}");
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback}"), None, &ann).status, 404);
        assert_eq!(h.call("GET", &format!("/api/v1/posts/{rollback}"), None, &mo).status, 200);

        // A membership the sync gave goes once its person leaves the source's topic.
        h.ok("DELETE", &format!("/api/v1/topics/{ops}/members/{mo_id}"), None, &admin);
        sync();
        assert!(!members(&h).contains(&mo_id), "the sync's own grant is taken back");
        assert!(members(&h).contains(&ann_id));
    }

    #[test]
    fn docs_sync_delivers_committed_webhooks_when_a_later_step_fails() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        h.ok("POST", "/api/v1/webhooks", Some(json!({ "url": "https://hooks.example.com/dumbslab", "events": ["post.*"] })), &admin);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Runbooks" })), &admin)["id"].as_str().unwrap().to_string();
        let (source, _) = gitlab_source(&h, &admin, &topic);
        let lab = Lab::new(&[("a.md", b"# A\n"), ("b.md", b"# B\n")]);
        let answer = |c: &HttpCall| lab.answer(c);
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        run_to_end(&h, job_of(&r), &answer);
        let ids = doc_ids(&h);

        // b.md goes (the listing step archives its post and commits), a.md changes, and then the
        // step that writes a.md is refused (a full workspace) and rolled back.
        lab.files.borrow_mut().remove("b.md");
        lab.put("a.md", b"# A\n\nChanged.\n");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let mut job = job_of(&r);
        let tree: Vec<HttpReply> = match step_once(&h, &mut job, vec![]) {
            Step::Fetch(calls) => calls.iter().map(&answer).collect(),
            other => panic!("{other:?}"),
        };
        let blobs: Vec<HttpReply> = match step_once(&h, &mut job, tree) {
            Step::Fetch(calls) => calls.iter().map(&answer).collect(),
            other => panic!("{other:?}"),
        };
        let refused = h
            .store
            .with_tx(|db| {
                let full = |_: &dyn dumbslab_core::Db| Some(dumbslab_core::ApiError::new(507, "storage_full", "This workspace is full."));
                let (step, _) = connect::guarded_step(db, &h.cfg, &mut job, blobs, chrono::Utc::now(), full);
                let ok = step.is_ok();
                (step, ok)
            })
            .unwrap();
        assert!(refused.is_err());
        // The archive committed and is announced; the refused change isn't.
        assert_eq!(events(&job.take_effects()), vec!["post.archived"]);
        assert_eq!(post(&h, &ids["b.md"], &admin)["status"], "archived");
        assert!(!post(&h, &ids["a.md"], &admin)["content"].as_str().unwrap().contains("Changed"), "rolled back");
    }

    #[test]
    fn docs_sync_skips_large_files_for_good() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Runbooks" })), &admin)["id"].as_str().unwrap().to_string();
        let (source, _) = gitlab_source(&h, &admin, &topic);
        // GitLab's listing has no sizes: these turn out too large only once read.
        let lab = Lab::new(&[]);
        for i in 0..21 {
            let name = format!("big-{i:02}.md");
            lab.put(&name, format!("# Big {i}\n").as_bytes());
            lab.too_large.borrow_mut().push(name);
        }
        lab.put("zz-small.md", b"# Small\n");
        let answer = |c: &HttpCall| lab.answer(c);
        let sync = || -> (Value, usize) {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            let (finish, sent) = drive(&h, job_of(&r), &answer);
            (filled(finish), sent.iter().filter(|c| c.url.contains("/blobs/")).count())
        };
        let (v, read) = sync();
        assert_eq!((v["created"].as_i64(), v["remaining"].as_i64(), read), (Some(0), Some(2), 20), "{v}");
        assert_eq!(v["skipped"].as_array().unwrap().len(), 20);
        // The next sync doesn't read them again, so the rest get their turn.
        let (v, read) = sync();
        assert_eq!((v["created"].as_i64(), v["remaining"].as_i64(), v["done"].as_bool(), read), (Some(1), Some(0), Some(true), 2), "{v}");
        assert_eq!(v["skipped"].as_array().unwrap().len(), 21, "{v}");
        assert!(v["skipped"][0]["reason"].as_str().unwrap().contains("larger than"), "{v}");
        let (v, read) = sync();
        assert_eq!((v["unchanged"].as_i64(), read), (Some(1), 0), "{v}");
        // A file that changes is tried again.
        lab.too_large.borrow_mut().retain(|p| p != "big-00.md");
        lab.put("big-00.md", b"# Big 0, smaller now\n");
        let (v, read) = sync();
        assert_eq!((v["created"].as_i64(), read), (Some(1), 1), "{v}");
    }

    // -----------------------------------------------------------------------
    // Docs through DumbSlab's GitHub App

    /// The throwaway key in the core's test data, with its PEM lines put back.
    fn app_key() -> String {
        let body = include_str!("../../core/src/sync/testdata/github-app-test-key.b64");
        format!("-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n", body.trim())
    }

    fn with_app(h: &mut H) {
        h.cfg.github_app = Some(dumbslab_core::sync::github_app::GitHubApp {
            app_id: "123".into(),
            slug: "dumbslab-test".into(),
            client_id: "Iv23liTEST".into(),
            client_secret: "gh-client-secret".into(),
            private_key: app_key(),
            webhook_secret: "gh-hook-secret".into(),
        });
    }

    fn location(r: &Res) -> String {
        assert_eq!(r.status, 302, "{} {}", r.status, r.body);
        r.header("location").unwrap().to_string()
    }

    /// Starts Connect GitHub in `who`'s browser session and returns the state GitHub hands back.
    fn start_install(h: &H, who: &Auth) -> String {
        let to = location(&h.raw("GET", "/sync/github/install", vec![], "", who));
        let state = to.strip_prefix("https://github.com/apps/dumbslab-test/installations/new?state=").unwrap_or_else(|| panic!("{to}"));
        urlencoding::decode(state).unwrap().into_owned()
    }

    fn callback(h: &H, who: &Auth, query: &str) -> Res {
        h.raw("GET", &format!("/sync/github/callback?{query}"), vec![], "", who)
    }

    /// GitHub, for the installer `ghu_admin`: they can access installation 42 (acme), whose
    /// repositories they can read are acme/docs and acme/site, and installation 43 once reinstalled.
    fn installer(call: &HttpCall) -> HttpReply {
        installer_of(&[42, 43])(call)
    }

    /// GitHub for an installer who can access these installations (each of them acme's).
    fn installer_of(ids: &[i64]) -> impl Fn(&HttpCall) -> HttpReply + use<> {
        let ids = ids.to_vec();
        move |call: &HttpCall| {
            if call.url == "https://github.com/login/oauth/access_token" {
                let body = call.body.clone().unwrap_or_default();
                assert!(body.contains("client_id=Iv23liTEST") && body.contains("client_secret=gh-client-secret"), "{body}");
                return ok(json!({ "access_token": "ghu_admin", "token_type": "bearer" }));
            }
            assert!(call.headers.contains(&("authorization".into(), "Bearer ghu_admin".into())), "{call:?} uses the installer's token");
            if let Some(page) = call.url.strip_prefix("https://api.github.com/user/installations?per_page=100&page=") {
                let list: Vec<Value> = ids
                    .iter()
                    .map(|id| json!({ "id": id, "account": { "login": "acme", "type": "Organization" }, "target_type": "Organization", "suspended_at": null }))
                    .collect();
                let page: usize = page.parse().unwrap();
                let items: Vec<Value> = list.chunks(100).nth(page - 1).map(<[Value]>::to_vec).unwrap_or_default();
                return ok(json!({ "total_count": ids.len(), "installations": items }));
            }
            for id in &ids {
                if call.url == format!("https://api.github.com/user/installations/{id}/repositories?per_page=100&page=1") {
                    return ok(json!({ "total_count": 2, "repositories": [
                        { "id": 7, "full_name": "acme/docs", "default_branch": "main", "private": true },
                        { "id": 8, "full_name": "acme/site", "default_branch": "trunk", "private": false },
                    ] }));
                }
            }
            ok(json!({ "total_count": 2, "repositories": [] }))
        }
    }

    fn redirect_of(finish: Finish) -> String {
        match finish {
            Finish::Redirect(url) => url,
            other => panic!("expected a redirect, got {other:?}"),
        }
    }

    fn background(r: &Res) -> Vec<Job> {
        r.effects
            .iter()
            .filter_map(|e| match e {
                Effect::Background(j) => Some(j.clone()),
                _ => None,
            })
            .collect()
    }

    fn links(effects: &[Effect]) -> Vec<(i64, bool)> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::GitHubInstallation(l) => Some((l.installation_id, l.linked)),
                _ => None,
            })
            .collect()
    }

    /// A delivery from DumbSlab's GitHub App, signed with `secret`.
    fn app_hook(h: &H, event: &str, body: &Value, secret: &str) -> Res {
        let body = body.to_string();
        let sig = format!("sha256={}", hmac_sha256_hex(secret, &body));
        hook(h, "/hooks/github", &body, &[("x-github-event", event), ("x-hub-signature-256", &sig), ("x-github-delivery", "d-1")])
    }

    fn source_of(h: &H, admin: &Auth) -> Value {
        h.ok("GET", "/api/v1/docs-sources", None, admin)["items"][0].clone()
    }

    #[test]
    fn github_app_connects_without_tokens_and_syncs_on_push() {
        let mut h = H::new();
        let (admin, admin_token) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let mo_cookie = sign_in(&h, "mo@acme.test", "password123");
        with_key(&mut h);

        // Without the App, Connect GitHub says so.
        assert_eq!(h.ok("GET", "/api/v1/docs-sources", None, &admin)["github_app"], false);
        let to = location(&h.raw("GET", "/sync/github/install", vec![], "", &admin));
        assert_eq!(to, "https://kb.test/settings/docs-sync?connect_error=unavailable&app=github");
        with_app(&mut h);
        assert_eq!(h.ok("GET", "/api/v1/docs-sources", None, &admin)["github_app"], true);

        // Only an admin, in their own browser session, starts it.
        let to = location(&h.raw("GET", "/sync/github/install", vec![], "", &mo_cookie));
        assert!(to.ends_with("connect_error=not_admin&app=github"), "{to}");
        let to = location(&h.raw("GET", "/sync/github/install", vec![], "", &admin_token));
        assert!(to.ends_with("connect_error=wrong_person&app=github"), "a token has no browser session: {to}");
        assert!(
            location(&h.raw("GET", "/sync/github/install", vec![], "", &Auth::None)).ends_with("connect_error=wrong_person&app=github")
        );

        // The state works once, for the session that started it.
        assert!(location(&callback(&h, &admin, "state=nope&code=c&installation_id=42")).ends_with("connect_error=expired_link&app=github"));
        let state = start_install(&h, &admin);
        let stored =
            count(&h, &format!("SELECT COUNT(*) FROM docs_connect_requests WHERE state_hash = '{}'", hex(&Sha256::digest(&state))));
        assert_eq!(stored, 1, "kept hashed");
        let other_session = sign_in(&h, "ada@acme.test", "correct horse");
        let q = format!("state={}&code=c&installation_id=42&setup_action=install", urlencoding::encode(&state));
        assert!(location(&callback(&h, &other_session, &q)).ends_with("connect_error=wrong_person&app=github"));
        assert!(location(&callback(&h, &admin, &q)).ends_with("connect_error=expired_link&app=github"), "used up");
        let state = start_install(&h, &admin);
        let r = callback(&h, &admin, &format!("state={}&setup_action=request", urlencoding::encode(&state)));
        assert!(location(&r).ends_with("connect_error=approval_requested&app=github"));
        let state = start_install(&h, &admin);
        assert!(
            location(&callback(&h, &admin, &format!("state={}&error=access_denied", urlencoding::encode(&state))))
                .ends_with("connect_error=declined&app=github")
        );

        // A forged installation id: GitHub doesn't list it for the installer, so it's refused.
        let state = start_install(&h, &admin);
        let r = callback(&h, &admin, &format!("state={}&code=c&installation_id=99&setup_action=install", urlencoding::encode(&state)));
        assert!(location(&r).ends_with("connect_error=failed&app=github"), "while the job runs, failing is the default");
        let (finish, _) = drive(&h, job_of(&r), &installer);
        assert_eq!(redirect_of(finish), "https://kb.test/settings/docs-sync?connect_error=not_yours&app=github");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM github_installations"), 0);

        // The real one: installed, checked against the installer's own account, saved.
        let state = start_install(&h, &admin);
        let r = callback(&h, &admin, &format!("state={}&code=c&installation_id=42&setup_action=install", urlencoding::encode(&state)));
        let (finish, sent, effects) = drive_all(&h, job_of(&r), &installer);
        assert_eq!(redirect_of(finish), "https://kb.test/settings/docs-sync?connected=github");
        assert_eq!(
            sent.len(),
            1 + dumbslab_core::sync::github_app::INSTALLATION_PAGES + dumbslab_core::sync::github_app::REPO_PAGES,
            "a code, pages of installations, and pages of repositories"
        );
        // The job leaves the directory link for the host (hosted workspaces forward deliveries by it).
        assert!(links(&effects).is_empty() && sent.iter().all(|c| c.url.starts_with("https://")), "a self-hosted server has no directory");
        let repos = h.ok("GET", "/api/v1/docs-sources/github", None, &admin);
        assert_eq!(repos["available"], true);
        assert_eq!(repos["connect_url"], "https://kb.test/sync/github/install");
        let inst = &repos["installations"][0];
        assert_eq!((inst["installation_id"].as_i64(), inst["account"].as_str()), (Some(42), Some("acme")));
        let names: Vec<&str> = inst["repositories"].as_array().unwrap().iter().map(|r| r["full_name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["acme/docs", "acme/site"]);
        assert_eq!(h.call("GET", "/api/v1/docs-sources/github", None, &mo).status, 403, "admins only");
        assert!(!h.ok("GET", "/api/v1/activity", None, &admin).to_string().contains("ghu_admin"), "the installer's token is never kept");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM activity WHERE event = 'github.connected'"), 1);

        // Adding a folder: only a repository the admin's account can read there, and no token.
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input =
            json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "folder": "handbook", "topic_id": topic });
        let refused = |change: Value| {
            let mut i = input.clone();
            i.as_object_mut().unwrap().extend(change.as_object().unwrap().clone());
            h.call("POST", "/api/v1/docs-sources", Some(i), &admin).status
        };
        assert_eq!(refused(json!({ "repository": "acme/secret" })), 404, "not one the admin showed they can read");
        assert_eq!(refused(json!({ "installation_id": 77 })), 404, "an installation nobody here connected");
        assert_eq!(refused(json!({ "token": "ghp_x" })), 400);
        assert_eq!(refused(json!({ "provider": "gitlab", "repository": "acme/docs" })), 400);
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input.clone()), &mo).status, 403);
        let created = h.call("POST", "/api/v1/docs-sources", Some(input.clone()), &admin);
        assert_eq!(created.status, 200, "{}", created.body);
        assert!(links(&created.effects).is_empty());
        let c = &created.body;
        assert_eq!((c["webhook_secret"].clone(), c["source"]["webhook_url"].clone()), (Value::Null, Value::Null), "no webhook to add");
        assert_eq!((c["source"]["connection"].as_str(), c["source"]["installation_id"].as_i64()), (Some("github_app"), Some(42)));
        assert_eq!((c["source"]["branch"].as_str(), c["source"]["has_token"].as_bool()), (Some("main"), Some(false)));
        let source = c["source"]["id"].as_str().unwrap().to_string();
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input), &admin).status, 409, "the same folder twice");
        let site = json!({ "provider": "github", "installation_id": 42, "repository": "ACME/site", "topic_id": topic });
        let site = h.ok("POST", "/api/v1/docs-sources", Some(site), &admin);
        assert_eq!(
            (site["source"]["repository"].as_str(), site["source"]["branch"].as_str()),
            (Some("acme/site"), Some("trunk")),
            "the default branch"
        );
        h.ok("DELETE", &format!("/api/v1/docs-sources/{}", site["source"]["id"].as_str().unwrap()), None, &admin);

        // Each sync mints a token that reads only this repository, then syncs with it.
        let repo = Repo::new(&[("README.md", b"# Handbook\n\nHello.\n"), ("guide.md", b"# Guide\n")]);
        let minted = RefCell::new(vec![]);
        let github = |c: &HttpCall| -> HttpReply {
            if c.url == "https://api.github.com/app/installations/42/access_tokens" {
                minted.borrow_mut().push(c.clone());
                return HttpReply {
                    status: 201,
                    body: json!({ "token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z",
                                  "repositories": [{ "id": 7, "full_name": "acme/docs" }] })
                    .to_string(),
                };
            }
            assert!(c.headers.contains(&("authorization".into(), "Bearer ghs_installation".into())), "{c:?}");
            repo.github(c)
        };
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &github);
        let v = filled(finish);
        assert_eq!((v["created"].as_i64(), v["done"].as_bool()), (Some(2), Some(true)), "{v}");
        assert_eq!(sent[0].url, "https://api.github.com/app/installations/42/access_tokens");
        let mint = minted.borrow()[0].clone();
        assert_eq!(
            serde_json::from_str::<Value>(mint.body.as_deref().unwrap()).unwrap(),
            json!({ "repository_ids": [7], "permissions": { "contents": "read" } })
        );
        let jwt = mint.headers.iter().find(|(k, _)| k == "authorization").unwrap().1.strip_prefix("Bearer ").unwrap().to_string();
        let claims: Value =
            serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(jwt.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        let now = chrono::Utc::now().timestamp();
        assert_eq!(claims["iss"], "Iv23liTEST");
        assert!(
            (now - 70..=now - 50).contains(&claims["iat"].as_i64().unwrap()) && claims["exp"].as_i64().unwrap() <= now + 600,
            "{claims}"
        );
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources WHERE secret LIKE '%ghs_%'"), 0, "tokens aren't kept");
        assert_eq!(post(&h, &doc_ids(&h)["README.md"], &mo)["title"], "Handbook");

        // No token or webhook secret to change; the branch can.
        for change in [json!({ "token": "ghp_x" }), json!({ "new_webhook_secret": true })] {
            assert_eq!(h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(change), &admin).status, 400);
        }
        h.ok("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "branch": "main" })), &admin);
        // Its own per-source webhook has no secret, so nothing can sign for it.
        let push = json!({ "ref": "refs/heads/main" }).to_string();
        let empty = format!("sha256={}", hmac_sha256_hex("", &push));
        assert_eq!(
            hook(&h, &format!("/hooks/docs/{source}"), &push, &[("x-github-event", "push"), ("x-hub-signature-256", &empty)]).status,
            401
        );

        // The App's webhook: signed with the App's secret, for installations connected here.
        let push = |installation: i64, repo_id: i64, branch: &str, name: &str| json!({ "ref": format!("refs/heads/{branch}"), "repository": { "id": repo_id, "full_name": name }, "installation": { "id": installation } });
        assert_eq!(app_hook(&h, "push", &push(42, 7, "main", "acme/docs"), "wrong").status, 401);
        assert_eq!(app_hook(&h, "ping", &json!({ "zen": "hi" }), "gh-hook-secret").body["status"], "pong");
        for (body, why) in [
            (push(77, 7, "main", "acme/docs"), "an installation nobody here connected"),
            (push(42, 8, "main", "acme/site"), "a repository no source syncs"),
            (push(42, 7, "feature", "acme/docs"), "another branch"),
        ] {
            let r = app_hook(&h, "push", &body, "gh-hook-secret");
            assert_eq!((r.status, r.body["status"].as_str(), r.effects.len()), (200, Some("ignored"), 0), "{why}: {}", r.body);
        }
        repo.put("guide.md", b"# Guide\n\nNew steps.\n");
        let r = app_hook(&h, "push", &push(42, 7, "main", "acme/docs"), "gh-hook-secret");
        assert_eq!((r.status, r.body["status"].as_str()), (200, Some("started")), "{}", r.body);
        let jobs = background(&r);
        assert_eq!(jobs.len(), 1, "the sync runs after the answer");
        let v = filled(drive(&h, jobs[0].clone(), &github).0);
        assert_eq!(v["updated"], 1, "{v}");
        // A second push while a sync runs is noted.
        let running = background(&app_hook(&h, "push", &push(42, 7, "main", "acme/docs"), "gh-hook-secret"));
        let r = app_hook(&h, "push", &push(42, 7, "main", "acme/docs"), "gh-hook-secret");
        assert!(background(&r).is_empty());
        drive(&h, running[0].clone(), &github);
        assert_eq!(source_of(&h, &admin)["pending"], true);

        // Changes to the installation only start a check of what GitHub says it is now.
        let gh = GitHubNow::new();
        let changed = |event: &str, body: &Value| check(&h, event, body, &gh);
        let lifecycle = |action: &str| json!({ "action": action, "installation": { "id": 42, "account": { "login": "acme" } } });

        // A repository taken out of the App: the source waits, its posts stay.
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        let removed =
            json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [{ "id": 7, "full_name": "acme/docs" }] });
        assert_eq!(changed("installation_repositories", &removed).0["removed"], 1);
        let s = source_of(&h, &admin);
        assert!(s["disconnected"].as_str().unwrap().contains("taken out"), "{s}");
        // Sync now syncs nothing, and asks GitHub again instead (still out of reach here).
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body["checking"].is_string() && r.body["created"] == 0, "{}", r.body);
        drive(&h, background(&r)[0].clone(), &|c| gh.answer(c));
        assert!(source_of(&h, &admin)["disconnected"].is_string());
        assert!(background(&app_hook(&h, "push", &push(42, 7, "main", "acme/docs"), "gh-hook-secret")).is_empty());
        let listed = h.ok("GET", "/api/v1/docs-sources/github", None, &admin);
        assert_eq!(listed["installations"][0]["repositories"].as_array().unwrap().len(), 1, "no longer offered");
        gh.repos.borrow_mut().extend([(7, "acme/docs"), (9, "acme/new")]);
        let added = json!({ "action": "added", "installation": { "id": 42 }, "repositories_added": [{ "id": 7, "full_name": "acme/docs" }, { "id": 9, "full_name": "acme/new" }] });
        changed("installation_repositories", &added);
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null, "back");
        let listed = h.ok("GET", "/api/v1/docs-sources/github", None, &admin);
        let names: Vec<&str> =
            listed["installations"][0]["repositories"].as_array().unwrap().iter().map(|r| r["full_name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["acme/docs", "acme/site"], "a new repository waits until an admin here shows they can read it");

        // Suspended, then unsuspended.
        *gh.state.borrow_mut() = "suspended";
        changed("installation", &lifecycle("suspend"));
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("suspended"));
        assert_eq!(h.ok("GET", "/api/v1/docs-sources/github", None, &admin)["installations"][0]["suspended"], true);
        *gh.state.borrow_mut() = "active";
        changed("installation", &lifecycle("unsuspend"));
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null);

        // Uninstalled: the source waits, the installation is forgotten, nothing is deleted.
        let posts_before = count(&h, "SELECT COUNT(*) FROM posts WHERE deleted_at IS NULL");
        *gh.state.borrow_mut() = "gone";
        let (v, effects) = changed("installation", &lifecycle("deleted"));
        assert_eq!(v["state"], "uninstalled");
        assert_eq!(links(&effects), vec![(42, false)], "the directory stops forwarding its deliveries here");
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("uninstalled"));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM github_installations"), 0);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM posts WHERE deleted_at IS NULL"), posts_before, "posts stay");
        assert_eq!(app_hook(&h, "push", &push(42, 7, "main", "acme/docs"), "gh-hook-secret").body["status"], "ignored");
        // Installing again (a new installation) picks the source back up.
        let state = start_install(&h, &admin);
        let r = callback(&h, &admin, &format!("state={}&code=c&installation_id=43&setup_action=install", urlencoding::encode(&state)));
        drive(&h, job_of(&r), &installer);
        let s = source_of(&h, &admin);
        assert_eq!((s["disconnected"].clone(), s["installation_id"].as_i64()), (Value::Null, Some(43)), "{s}");

        // Activity about the App is for admins only.
        let feed = h.ok("GET", "/api/v1/activity?limit=200", None, &mo).to_string();
        assert!(!feed.contains("github.") && !feed.contains("docs_source"), "{feed}");
        assert!(h.ok("GET", "/api/v1/activity?limit=200", None, &admin).to_string().contains("github.uninstalled"));
    }

    /// GitHub's view of installation 42 now, for checks of it: `active`, `suspended` or `gone`; the
    /// repositories it can reach, by id and current name; and names other repositories now have
    /// (name → their id), which it may or may not reach.
    struct GitHubNow {
        state: RefCell<&'static str>,
        repos: RefCell<Vec<(i64, &'static str)>>,
        taken: RefCell<Vec<(&'static str, i64)>>,
        /// Answers GitHub can't give just now (5xx), for a while.
        down: RefCell<bool>,
    }

    impl GitHubNow {
        fn new() -> GitHubNow {
            GitHubNow {
                state: RefCell::new("active"),
                repos: RefCell::new(vec![(7, "acme/docs"), (8, "acme/site")]),
                taken: RefCell::new(vec![]),
                down: RefCell::new(false),
            }
        }

        fn answer(&self, c: &HttpCall) -> HttpReply {
            if *self.down.borrow() {
                return HttpReply { status: 503, body: "{}".into() };
            }
            let state = *self.state.borrow();
            if c.url == "https://api.github.com/app/installations/42" {
                assert!(c.headers.iter().any(|(k, v)| k == "authorization" && v.starts_with("Bearer ey")), "the App's JWT");
                return match state {
                    "gone" => HttpReply { status: 404, body: "{}".into() },
                    s => {
                        ok(json!({ "id": 42, "suspended_at": if s == "suspended" { json!("2026-10-31T00:00:00Z") } else { Value::Null } }))
                    }
                };
            }
            if c.url == "https://api.github.com/app/installations/42/access_tokens" {
                assert_eq!(
                    serde_json::from_str::<Value>(c.body.as_deref().unwrap()).unwrap(),
                    json!({ "permissions": { "metadata": "read" } })
                );
                return match state {
                    "active" => HttpReply { status: 201, body: json!({ "token": "ghs_list" }).to_string() },
                    "gone" => HttpReply { status: 404, body: "{}".into() },
                    _ => HttpReply { status: 403, body: "{}".into() },
                };
            }
            assert!(c.headers.contains(&("authorization".into(), "Bearer ghs_list".into())), "{c:?}");
            assert!(!c.url.contains("/installation/repositories"), "a check never lists the whole installation");
            let repos = self.repos.borrow();
            let found = |id: i64| repos.iter().find(|(r, _)| *r == id).map(|(id, name)| ok(json!({ "id": id, "full_name": name })));
            if let Some(name) = c.url.strip_prefix("https://api.github.com/repos/") {
                if let Some((_, id)) = self.taken.borrow().iter().find(|(n, _)| *n == name) {
                    return found(*id).unwrap_or(HttpReply { status: 404, body: "{}".into() });
                }
                return repos
                    .iter()
                    .find(|(_, n)| *n == name)
                    .and_then(|(id, _)| found(*id))
                    .unwrap_or(HttpReply { status: 404, body: "{}".into() });
            }
            if let Some(id) = c.url.strip_prefix("https://api.github.com/repositories/") {
                return found(id.parse().unwrap()).unwrap_or(HttpReply { status: 404, body: "{}".into() });
            }
            panic!("unexpected {c:?}");
        }
    }

    /// The check a change to an installation starts, from the delivery.
    fn check_of(h: &H, event: &str, body: &Value) -> Job {
        let r = app_hook(h, event, body, "gh-hook-secret");
        assert_eq!((r.status, r.body["status"].as_str()), (200, Some("checking")), "{}", r.body);
        let jobs = background(&r);
        assert_eq!(jobs.len(), 1);
        jobs[0].clone()
    }

    /// Delivers a change to installation 42 and runs its check against `gh`: what it found, and its
    /// effects.
    fn check(h: &H, event: &str, body: &Value, gh: &GitHubNow) -> (Value, Vec<Effect>) {
        let (finish, _, effects) = drive_all(h, check_of(h, event, body), &|c| gh.answer(c));
        (filled(finish), effects)
    }

    #[test]
    fn removing_a_source_or_its_topic_waits_for_its_sync() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input = json!({ "provider": "github", "repository": "acme/docs", "folder": "handbook", "topic_id": topic, "token": "ghp_x" });
        let source = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        let repo = Repo::new(&[("README.md", b"# Handbook\n")]);
        let answer = |c: &HttpCall| repo.github(c);
        filled(drive(&h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin)), &answer).0);

        // While a sync runs, neither the source nor its topic can go.
        let running = job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin));
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("Try again"));
        assert_eq!(h.call("DELETE", &format!("/api/v1/topics/{topic}"), None, &admin).status, 409);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM topics WHERE name = 'Handbook'"), 1);
        drive(&h, running, &answer);

        // Deleting the topic then removes its source the same way, and its posts stay.
        h.ok("DELETE", &format!("/api/v1/topics/{topic}"), None, &admin);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources"), 0);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM activity WHERE event = 'docs_source.deleted'"), 1);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM posts WHERE title = 'Handbook' AND deleted_at IS NULL"), 1);
    }

    /// Connects installation 42 in `who`'s session: its redirect, and the requests and effects the
    /// job made, with `answer` for GitHub (and, hosted, the directory).
    fn connect_github(h: &H, who: &Auth, query: &str, answer: &dyn Fn(&HttpCall) -> HttpReply) -> (String, Vec<HttpCall>) {
        let state = start_install(h, who);
        let r = callback(h, who, &format!("state={}&code=c{query}", urlencoding::encode(&state)));
        let (finish, sent, _) = drive_all(h, job_of(&r), answer);
        (redirect_of(finish), sent)
    }

    fn directory(status: u16, code: &str) -> HttpReply {
        HttpReply { status, body: json!({ "error": { "code": code, "message": "…" } }).to_string() }
    }

    fn forwarding(h: &H, admin: &Auth) -> Value {
        h.ok("GET", "/api/v1/docs-sources/github", None, admin)["installations"][0]["forwarding"].clone()
    }

    #[test]
    fn hosted_github_connections_register_with_the_directory() {
        use dumbslab_core::sync::github_app::DIRECTORY_LINK_URL;
        let (mut h, admin) = hosted(None);
        with_key(&mut h);
        with_app(&mut h);
        let asked = RefCell::new(vec![]);
        let refusing = |c: &HttpCall| {
            if c.url == DIRECTORY_LINK_URL {
                asked.borrow_mut().push(serde_json::from_str::<Value>(c.body.as_deref().unwrap()).unwrap());
                return directory(409, "installation_full");
            }
            installer(c)
        };

        // The installation already serves as many workspaces as it may: connected, but the admin is
        // told GitHub's pushes can't reach this workspace.
        let (to, _) = connect_github(&h, &admin, "&installation_id=42&setup_action=install", &refusing);
        assert_eq!(to, "https://acme.kb.test/settings/docs-sync?connect_error=installation_full&app=github");
        assert_eq!(asked.borrow()[0], json!({ "installation_id": 42, "linked": true }));
        assert_eq!(forwarding(&h, &admin), "full");

        // Each sync asks again until the directory has it.
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input =
            json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "folder": "handbook", "topic_id": topic });
        let source = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        let repo = Repo::new(&[("README.md", b"# Handbook\n")]);
        let repo = &repo;
        let github = |directory_answer: HttpReply| {
            move |c: &HttpCall| -> HttpReply {
                if c.url == DIRECTORY_LINK_URL {
                    return directory_answer.clone();
                }
                if c.url.ends_with("/access_tokens") {
                    return HttpReply { status: 201, body: json!({ "token": "ghs_installation", "repositories": [] }).to_string() };
                }
                repo.github(c)
            }
        };
        let sync = |answer: &dyn Fn(&HttpCall) -> HttpReply| {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            let (finish, sent) = drive(&h, job_of(&r), answer);
            filled(finish);
            sent.iter().filter(|c| c.url == DIRECTORY_LINK_URL).count()
        };
        assert_eq!(sync(&github(HttpReply::default())), 1, "asked again; the directory didn't answer");
        assert_eq!(forwarding(&h, &admin), "full", "nothing learned");
        assert_eq!(sync(&github(HttpReply { status: 200, body: json!({ "ok": true }).to_string() })), 1);
        assert_eq!(forwarding(&h, &admin), "ok");
        assert_eq!(sync(&github(HttpReply::default())), 0, "recorded: not asked again");

        // Connecting when the directory has room says so plainly.
        db_run(&h, |db| db.execute("UPDATE github_installations SET forwarding = NULL", &[]));
        assert_eq!(forwarding(&h, &admin), "pending");
        let accepting = |c: &HttpCall| if c.url == DIRECTORY_LINK_URL { ok(json!({ "ok": true })) } else { installer(c) };
        let (to, _) = connect_github(&h, &admin, "&installation_id=42&setup_action=install", &accepting);
        assert_eq!(to, "https://acme.kb.test/settings/docs-sync?connected=github");
        assert_eq!(forwarding(&h, &admin), "ok");
    }

    #[test]
    fn github_connections_without_an_installation_hint() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        // GitHub didn't say which installation: every one the installer can access is connected,
        // not the first few.
        let (to, sent) = connect_github(&h, &admin, "", &installer_of(&[41, 42, 43, 44]));
        assert_eq!(to, "https://kb.test/settings/docs-sync?connected=github");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM github_installations"), 4);
        assert!(sent.iter().any(|c| c.url.ends_with("/user/installations/44/repositories?per_page=100&page=1")));
        let listed = h.ok("GET", "/api/v1/docs-sources/github", None, &admin);
        assert_eq!(listed["installations"][3]["forwarding"], "direct", "a self-hosted server gets deliveries itself");
        // Too many to connect them all: the admin chooses, by starting from the installation.
        let many: Vec<i64> = (100..112).collect();
        let (to, _) = connect_github(&h, &admin, "", &installer_of(&many));
        assert_eq!(to, "https://kb.test/settings/docs-sync?connect_error=choose_installation&app=github");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM github_installations"), 4, "none of them");
        // With a hint past the first page of installations, it's still found.
        let (to, _) = connect_github(&h, &admin, "&installation_id=111&setup_action=install", &installer_of(&many));
        assert_eq!(to, "https://kb.test/settings/docs-sync?connected=github");
    }

    #[test]
    fn github_repository_changes_are_checked_against_githubs_list() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &installer);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input = json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "topic_id": topic });
        let source = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        let gh = GitHubNow::new();
        let picker = |h: &H| -> Vec<String> {
            h.ok("GET", "/api/v1/docs-sources/github", None, &admin)["installations"][0]["repositories"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["full_name"].as_str().unwrap().to_string())
                .collect()
        };

        // From all repositories to selected ones: GitHub may name none of those left out, so the
        // list is checked, and acme/docs stops syncing (its posts stay).
        gh.repos.borrow_mut().retain(|(id, _)| *id == 8);
        let switched =
            json!({ "action": "removed", "repository_selection": "selected", "installation": { "id": 42 }, "repositories_removed": [] });
        assert_eq!(check(&h, "installation_repositories", &switched, &gh).0["removed"], 1);
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("taken out"));
        assert_eq!(picker(&h), vec!["acme/site"]);
        // GitHub redelivers it (same delivery id): handled again, the same way.
        assert_eq!(check(&h, "installation_repositories", &switched, &gh).0["removed"], 0);

        // Put back, also without being named: the next change brings it back.
        gh.repos.borrow_mut().push((7, "acme/docs"));
        let added =
            json!({ "action": "added", "repository_selection": "selected", "installation": { "id": 42 }, "repositories_added": [] });
        check(&h, "installation_repositories", &added, &gh);
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null);
        assert_eq!(picker(&h), vec!["acme/docs", "acme/site"]);

        // A sync whose repository the installation can't reach (GitHub answers 422) doesn't decide
        // that itself: it asks for a check, which does.
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        let refused = |_: &HttpCall| HttpReply { status: 422, body: "{}".into() };
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, _, effects) = drive_all(&h, job_of(&r), &refused);
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("checking")), "{finish:?}");
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null, "not by itself");
        let checks: Vec<Job> = effects.into_iter().filter_map(|e| if let Effect::Background(j) = e { Some(j) } else { None }).collect();
        assert_eq!(checks.len(), 1);
        filled(drive(&h, checks[0].clone(), &|c| gh.answer(c)).0);
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("taken out"));

        // Uninstalled, and redelivered: the second finds nothing left to do.
        *gh.state.borrow_mut() = "gone";
        let deleted = json!({ "action": "deleted", "installation": { "id": 42, "account": { "login": "acme" } } });
        assert_eq!(check(&h, "installation", &deleted, &gh).0["state"], "uninstalled");
        let again = app_hook(&h, "installation", &deleted, "gh-hook-secret");
        assert_eq!((again.status, again.body["status"].as_str()), (200, Some("ignored")));
    }

    /// One step of a job like a host runs it: committed when it works, rolled back when it fails.
    /// Returns its result and, when it failed, the notice the host sends.
    fn step_with(h: &H, job: &mut Job, replies: Vec<HttpReply>) -> (dumbslab_core::ApiResult<Step>, Option<HttpCall>) {
        let (out, next) = h
            .store
            .with_tx(|db| {
                let mut j = job.clone();
                let (step, notice) = connect::guarded_step(db, &h.cfg, &mut j, replies, chrono::Utc::now(), |_| None);
                let ok = step.is_ok();
                (((step, notice), j), ok)
            })
            .unwrap();
        *job = next;
        out
    }

    /// An installation connected here, with a source on acme/docs (repository 7).
    fn github_with_a_source() -> (H, Auth, String) {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &installer);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input = json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "topic_id": topic });
        let source = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        (h, admin, source)
    }

    fn gens(h: &H) -> (i64, i64) {
        let r = db_run(h, |db| db.one("SELECT requested_gen, applied_gen FROM github_installations WHERE id = 42", &[])).unwrap();
        (r.i64("requested_gen"), r.i64("applied_gen"))
    }

    fn checks_in(effects: Vec<Effect>) -> Vec<Job> {
        effects.into_iter().filter_map(|e| if let Effect::Background(j) = e { Some(j) } else { None }).collect()
    }

    #[test]
    fn checks_of_an_installation_run_one_at_a_time_and_none_is_lost() {
        let (h, admin, _) = github_with_a_source();
        let gh = GitHubNow::new();
        let answer = |c: &HttpCall| gh.answer(c);
        let change = json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] });

        // A burst of ten changes: the first starts a check, the rest only note there's more to
        // read. The check applies what it read and chains one more, which catches up: two checks.
        let mut started = vec![];
        for _ in 0..10 {
            let r = app_hook(&h, "installation_repositories", &change, "gh-hook-secret");
            assert_eq!(r.body["status"], "checking");
            started.extend(background(&r));
        }
        assert_eq!(started.len(), 1, "one check at a time");
        let (finish, _, effects) = drive_all(&h, started.remove(0), &answer);
        assert_eq!(filled(finish)["state"], "active");
        assert_eq!(gens(&h), (10, 1), "what it read was at least as fresh as the change it started for");
        let chained = checks_in(effects);
        assert_eq!(chained.len(), 1, "one more for the changes that came in meanwhile");
        let (_, _, effects) = drive_all(&h, chained[0].clone(), &answer);
        assert_eq!(gens(&h), (10, 10));
        assert!(checks_in(effects).is_empty(), "caught up: two checks in all");

        // A check that took too long loses its hold. The change after it starts another, which
        // fails (GitHub is down) and waits a while; the slow one, back, stops without asking
        // GitHub anything. The change stays owed and is checked once the wait is over.
        let slow = check_of(&h, "installation_repositories", &change);
        db_run(&h, |db| db.execute("UPDATE github_installations SET checking_until = '2000-01-01T00:00:00.000Z x'", &[]));
        let newer = check_of(&h, "installation_repositories", &change);
        *gh.down.borrow_mut() = true;
        assert!(matches!(drive(&h, newer, &answer).0, Finish::Fail(_)));
        *gh.down.borrow_mut() = false;
        let (finish, sent) = drive(&h, slow, &answer);
        assert_eq!((filled(finish)["state"].clone(), sent.len()), (json!("superseded"), 0));
        assert_eq!(gens(&h), (12, 10), "still owed");
        let r = h.call("GET", "/api/v1/docs-sources/github", None, &admin);
        assert!(background(&r).is_empty(), "not before the wait is over");
        db_run(&h, |db| db.execute("UPDATE github_installations SET next_check_at = '2000-01-01T00:00:00.000Z'", &[]));
        let r = h.call("GET", "/api/v1/docs-sources/github", None, &admin);
        let retried = background(&r);
        assert_eq!(retried.len(), 1, "Settings › Docs sync picks it up");
        drive(&h, retried[0].clone(), &answer);
        assert_eq!(gens(&h), (12, 12));
    }

    #[test]
    fn a_late_422_never_disconnects_a_restored_repository() {
        let (h, admin, source) = github_with_a_source();
        let gh = GitHubNow::new();
        // A sync asks for its token; before GitHub's 422 (from when acme/docs was out of the App)
        // arrives, the repository is put back and a check finds it reachable.
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let mut sync = job_of(&r);
        let Ok(Step::Fetch(_)) = step_with(&h, &mut sync, vec![]).0 else { panic!("the token request") };
        let added =
            json!({ "action": "added", "installation": { "id": 42 }, "repositories_added": [{ "id": 7, "full_name": "acme/docs" }] });
        check(&h, "installation_repositories", &added, &gh);
        let (result, _) = step_with(&h, &mut sync, vec![HttpReply { status: 422, body: "{}".into() }]);
        assert!(matches!(result, Ok(Step::Done(Finish::Fail(_)))), "{result:?}");
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null, "the late 422 decides nothing");
        // It asked for a check, which finds the repository reachable: still connected.
        let asked = checks_in(sync.take_effects());
        assert_eq!(asked.len(), 1);
        let (finish, _, effects) = drive_all(&h, asked[0].clone(), &|c| gh.answer(c));
        assert_eq!(filled(finish)["state"], "active");
        assert!(checks_in(effects).is_empty());
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null);
        assert_eq!(gens(&h), (2, 2));
    }

    #[test]
    fn checks_read_each_sources_repository_whatever_the_installations_size() {
        let (h, admin, _) = github_with_a_source();
        // A repository far down a large installation (not among the first 500 it lists), which the
        // admin's account could read when they connected.
        db_run(&h, |db| {
            db.execute("INSERT INTO github_repositories (installation_id, id, full_name, default_branch, private) VALUES (42, 777, 'acme/zz-big', 'main', 1)", &[])
        });
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Big" })), &admin)["id"].as_str().unwrap().to_string();
        let input = json!({ "provider": "github", "installation_id": 42, "repository": "acme/zz-big", "topic_id": topic });
        let big = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        let disconnected = |h: &H, id: &str| -> Value {
            h.ok("GET", "/api/v1/docs-sources", None, &admin)["items"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap()["disconnected"].clone()
        };
        let gh = GitHubNow::new();
        let change = json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] });
        // Out of reach: it waits.
        check(&h, "installation_repositories", &change, &gh);
        assert!(disconnected(&h, &big).as_str().unwrap().contains("taken out"));
        // Back, among hundreds of others: GitHub is asked about it alone, and it comes back.
        gh.repos.borrow_mut().push((777, "acme/zz-big"));
        check(&h, "installation_repositories", &change, &gh);
        assert_eq!(disconnected(&h, &big), Value::Null);
        // Renamed on GitHub: found by its id, so it stays connected, under its new name.
        gh.repos.borrow_mut().retain(|(id, _)| *id != 777);
        gh.repos.borrow_mut().push((777, "acme/huge"));
        check(&h, "installation_repositories", &change, &gh);
        assert_eq!(disconnected(&h, &big), Value::Null);
        let names: Vec<String> = h.ok("GET", "/api/v1/docs-sources/github", None, &admin)["installations"][0]["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["full_name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"acme/huge".to_string()), "{names:?}");
    }

    #[test]
    fn a_renamed_repository_whose_old_name_is_taken_stays_connected() {
        let (h, admin, source) = github_with_a_source();
        let gh = GitHubNow::new();
        let change = json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] });
        // acme/docs is renamed acme/handbook; a private repository the App can't reach takes the
        // name acme/docs.
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        gh.repos.borrow_mut().push((7, "acme/handbook"));
        gh.taken.borrow_mut().push(("acme/docs", 99));
        for _ in 0..2 {
            check(&h, "installation_repositories", &change, &gh);
            let s = source_of(&h, &admin);
            assert_eq!((s["disconnected"].clone(), s["repository"].as_str()), (Value::Null, Some("acme/handbook")), "{s}");
        }
        assert_eq!(source_of(&h, &admin)["id"], source.as_str());
        let names: Vec<String> = h.ok("GET", "/api/v1/docs-sources/github", None, &admin)["installations"][0]["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["full_name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"acme/handbook".to_string()) && !names.contains(&"acme/docs".to_string()), "{names:?}");
        // Out of reach for real (not found by id, and its name is someone else's): it waits.
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        gh.taken.borrow_mut().push(("acme/handbook", 98));
        check(&h, "installation_repositories", &change, &gh);
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("taken out"));
    }

    #[test]
    fn renames_never_make_two_sources_sync_one_folder() {
        let (h, admin, first) = github_with_a_source();
        let topic = source_of(&h, &admin)["topic"]["id"].as_str().unwrap().to_string();
        let add = |repo: &str, extra: Value| {
            let mut input = json!({ "provider": "github", "repository": repo, "topic_id": topic });
            input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            h.call("POST", "/api/v1/docs-sources", Some(input), &admin)
        };
        let id_of = |r: Res| {
            assert_eq!(r.status, 200, "{}", r.body);
            r.body["source"]["id"].as_str().unwrap().to_string()
        };
        let listed = |id: &str| {
            let list = h.ok("GET", "/api/v1/docs-sources", None, &admin);
            list["items"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap().clone()
        };
        let disconnected = |id: &str| listed(id)["disconnected"].clone();
        let refused = |r: Res| {
            assert_eq!(r.status, 409, "{}", r.body);
            assert_eq!(r.body["error"]["message"], "that folder already syncs into that topic");
        };

        // acme/docs is renamed acme/handbook on GitHub. Before DumbSlab hears of it, the admin
        // connects GitHub again and picks the folder again under the new name: it's the same
        // repository (by its id), so that's refused.
        let renamed = |c: &HttpCall| {
            let mut r = installer(c);
            r.body = r.body.replace("\"acme/docs\"", "\"acme/handbook\"");
            r
        };
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &renamed);
        refused(add("acme/handbook", json!({ "installation_id": 42 })));
        // Another branch is another folder. Moving it onto the first one's branch is refused too.
        let token_dev = id_of(add("acme/manual", json!({ "branch": "dev", "token": "ghp_x" })));
        let app_dev = id_of(add("acme/handbook", json!({ "installation_id": 42, "branch": "dev" })));
        refused(h.call("PATCH", &format!("/api/v1/docs-sources/{app_dev}"), Some(json!({ "branch": "main" })), &admin));
        let token_main = id_of(add("acme/manual", json!({ "token": "ghp_x" })));

        // GitHub renames it again, to acme/manual, which two token sources (added later than one
        // App source, earlier than the other) sync. Where two now sync the same folder, the older
        // keeps syncing and the newer waits, saying why; nothing is deleted.
        let gh = GitHubNow::new();
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        gh.repos.borrow_mut().push((7, "acme/manual"));
        check(
            &h,
            "installation_repositories",
            &json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] }),
            &gh,
        );
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources WHERE repo = 'acme/manual'"), 4);
        assert_eq!((disconnected(&first), disconnected(&token_dev)), (Value::Null, Value::Null), "the older ones");
        for newer in [&token_main, &app_dev] {
            assert!(disconnected(newer).as_str().unwrap().contains("Another source already syncs this folder"), "{newer}");
        }
        let r = h.call("POST", &format!("/api/v1/docs-sources/{token_main}/sync"), None, &admin);
        assert_eq!((r.status, r.body["error"]["code"].as_str()), (409, Some("duplicate")), "{}", r.body);
        let down = |_: &HttpCall| HttpReply { status: 503, body: "{}".into() };
        drive(&h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{first}/sync"), None, &admin)), &down);
        // A push starts the newer one's sync like any other. Once its token says what the
        // repository is called now, it stops before reading anything.
        let push = json!({ "ref": "refs/heads/dev", "repository": { "id": 7, "full_name": "acme/manual" }, "installation": { "id": 42 } });
        let jobs = background(&app_hook(&h, "push", &push, "gh-hook-secret"));
        assert_eq!(jobs.len(), 1);
        let mint = |c: &HttpCall| {
            assert_eq!(c.url, "https://api.github.com/app/installations/42/access_tokens", "only a token");
            let body = json!({ "token": "ghs_x", "expires_at": "2099-01-01T00:00:00Z", "repositories": [{ "id": 7, "full_name": "acme/manual" }] });
            HttpReply { status: 201, body: body.to_string() }
        };
        let (finish, sent) = drive(&h, jobs[0].clone(), &mint);
        assert!(matches!(finish, Finish::Fail(_)) && sent.len() == 1);
        assert_eq!(listed(&app_dev)["last_error"], dumbslab_core::sync::docs::DUPLICATE);

        // With the older one gone, the newer one syncs again.
        h.ok("DELETE", &format!("/api/v1/docs-sources/{first}"), None, &admin);
        h.ok("DELETE", &format!("/api/v1/docs-sources/{token_dev}"), None, &admin);
        assert_eq!((disconnected(&token_main), disconnected(&app_dev)), (Value::Null, Value::Null));
        job_of(&h.call("POST", &format!("/api/v1/docs-sources/{token_main}/sync"), None, &admin));
    }

    #[test]
    fn a_renamed_repositorys_posts_link_to_its_new_name() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &installer);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input =
            json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "folder": "handbook", "topic_id": topic });
        let source = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        let repo = Repo::new(&[("README.md", b"# Handbook\n\nSee [the API](../api/README.md).\n"), ("guide.md", b"# Guide\n")]);
        // GitHub, with the repository under its current name: the minted token names it, and the
        // repository answers only there.
        let name = RefCell::new("acme/docs");
        let github = |c: &HttpCall| -> HttpReply {
            let now = *name.borrow();
            if c.url == "https://api.github.com/app/installations/42/access_tokens" {
                let body = json!({ "token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z",
                                   "repositories": [{ "id": 7, "full_name": now }] });
                return HttpReply { status: 201, body: body.to_string() };
            }
            match c.url.strip_prefix(&format!("https://api.github.com/repos/{now}/")) {
                Some(rest) => repo.github(&HttpCall { url: format!("https://api.github.com/repos/acme/docs/{rest}"), ..c.clone() }),
                None => HttpReply { status: 404, body: "{}".into() },
            }
        };
        let sync = || filled(drive(&h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin)), &github).0);
        let readme = || post(&h, &doc_ids(&h)["README.md"], &admin)["content"].as_str().unwrap().to_string();
        assert_eq!(sync()["created"], 2);
        assert!(readme().contains("[the API](https://github.com/acme/docs/blob/main/api/README.md)"), "{}", readme());

        // Renamed on GitHub, and the next sync's token says so: the source follows, and its files,
        // unchanged in the repository, are rendered again with the new name.
        *name.borrow_mut() = "acme/handbook";
        let r = sync();
        assert_eq!((r["updated"].as_u64(), r["unchanged"].as_u64(), r["done"].as_bool()), (Some(1), Some(1), Some(true)), "{r}");
        assert_eq!(source_of(&h, &admin)["repository"], "acme/handbook");
        assert!(readme().contains("[the API](https://github.com/acme/handbook/blob/main/api/README.md)"), "{}", readme());
        assert_eq!((sync()["unchanged"].as_u64(), sync()["updated"].as_u64()), (Some(2), Some(0)), "then nothing to do");

        // Renamed again, and a check of the installation hears of it first: the same.
        *name.borrow_mut() = "acme/manual";
        let gh = GitHubNow::new();
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        gh.repos.borrow_mut().push((7, "acme/manual"));
        check(
            &h,
            "installation_repositories",
            &json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] }),
            &gh,
        );
        assert_eq!(source_of(&h, &admin)["repository"], "acme/manual");
        assert_eq!(sync()["updated"], 1);
        assert!(readme().contains("[the API](https://github.com/acme/manual/blob/main/api/README.md)"), "{}", readme());
    }

    #[test]
    fn a_repository_that_takes_a_folders_old_name_is_another_repository() {
        let (h, admin, first) = github_with_a_source();
        let topic = source_of(&h, &admin)["topic"]["id"].as_str().unwrap().to_string();
        // acme/docs (repository 7) is transferred out of the installation, and repository 9 takes
        // its name. The folder on 7 is disconnected, and keeps the name it had.
        let gh = GitHubNow::new();
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        gh.repos.borrow_mut().push((9, "acme/docs"));
        check(
            &h,
            "installation_repositories",
            &json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] }),
            &gh,
        );
        let s = source_of(&h, &admin);
        assert!(s["disconnected"].as_str().unwrap().contains("taken out"), "{s}");
        assert_eq!(s["repository"], "acme/docs");

        // Connect GitHub again: the picker has repository 9 as acme/docs. The same folder of it is
        // another repository's, so it's added, and it syncs.
        let nine = |c: &HttpCall| {
            let mut r = installer(c);
            if c.url.contains("/user/installations/42/repositories") {
                let mut v: Value = serde_json::from_str(&r.body).unwrap();
                for repo in v["repositories"].as_array_mut().unwrap() {
                    if repo["id"] == 7 {
                        repo["id"] = json!(9);
                    }
                }
                r.body = v.to_string();
            }
            r
        };
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &nine);
        let input =
            json!({ "provider": "github", "installation_id": 42, "repository_id": 9, "repository": "acme/docs", "topic_id": topic });
        let r = h.call("POST", "/api/v1/docs-sources", Some(input), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let second = r.body["source"]["id"].as_str().unwrap().to_string();
        assert_eq!(r.body["source"]["disconnected"], Value::Null);
        job_of(&h.call("POST", &format!("/api/v1/docs-sources/{second}/sync"), None, &admin));
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("taken out"), "the first still waits for 7");
        assert_eq!(source_of(&h, &admin)["id"], first.as_str());
        // A token folder has no id to tell them apart: by name, it's the same folder.
        let token = json!({ "provider": "github", "repository": "acme/docs", "topic_id": topic, "token": "ghp_x" });
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(token), &admin).status, 409);
    }

    #[test]
    fn the_picked_repository_is_added_whatever_its_name_is_now() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &installer);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let picked = h.ok("GET", "/api/v1/docs-sources/github", None, &admin)["installations"][0]["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["full_name"] == "acme/docs")
            .unwrap()
            .clone();
        assert_eq!(picked["id"], 7);
        // Meanwhile acme/docs is renamed acme/handbook, repository 9 takes the name acme/docs, and
        // someone connects GitHub again, so DumbSlab knows both.
        let moved = |c: &HttpCall| {
            let mut r = installer(c);
            if c.url.contains("/user/installations/42/repositories") {
                r.body = json!({ "total_count": 2, "repositories": [
                    { "id": 7, "full_name": "acme/handbook", "default_branch": "main", "private": true },
                    { "id": 9, "full_name": "acme/docs", "default_branch": "main", "private": true },
                ] })
                .to_string();
            }
            r
        };
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &moved);
        // The admin adds what they picked: repository 7, under its name now.
        let input = json!({ "provider": "github", "installation_id": 42, "repository_id": picked["id"], "repository": picked["full_name"], "topic_id": topic });
        let r = h.call("POST", "/api/v1/docs-sources", Some(input), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.body["source"]["repository"], "acme/handbook");
        let id = r.body["source"]["id"].as_str().unwrap().to_string();
        assert_eq!(count(&h, &format!("SELECT repo_id FROM docs_source_links WHERE source_id = '{id}'")), 7);
        // A name alone is looked up once, as it is now, and its id kept.
        let by_name =
            json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "folder": "guides", "topic_id": topic });
        let id = h.ok("POST", "/api/v1/docs-sources", Some(by_name), &admin)["source"]["id"].as_str().unwrap().to_string();
        assert_eq!(count(&h, &format!("SELECT repo_id FROM docs_source_links WHERE source_id = '{id}'")), 9);
        let no_installation =
            json!({ "provider": "github", "repository_id": 7, "repository": "acme/docs", "topic_id": topic, "token": "ghp_x" });
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(no_installation), &admin).status, 400);
        let unknown =
            json!({ "provider": "github", "installation_id": 42, "repository_id": 77, "repository": "acme/docs", "topic_id": topic });
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(unknown), &admin).status, 404);
    }

    #[test]
    fn a_file_moved_while_renders_are_owed_keeps_its_post() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &installer);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input =
            json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "folder": "handbook", "topic_id": topic });
        let source = h.ok("POST", "/api/v1/docs-sources", Some(input), &admin)["source"]["id"].as_str().unwrap().to_string();
        // One more file than a run renders: 20 docs, then `zz.md` last.
        let mut files: Vec<(String, Vec<u8>)> =
            (0..20).map(|i| (format!("doc{i:02}.md"), format!("# Doc {i}\n\nSee [the API](../api/README.md).\n").into_bytes())).collect();
        files.push(("zz.md".into(), b"# Last\n\nSee [the API](../api/README.md).\n".to_vec()));
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect();
        let repo = Repo::new(&refs);
        let name = RefCell::new("acme/docs");
        let github = |c: &HttpCall| -> HttpReply {
            let now = *name.borrow();
            if c.url == "https://api.github.com/app/installations/42/access_tokens" {
                let body = json!({ "token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z",
                                   "repositories": [{ "id": 7, "full_name": now }] });
                return HttpReply { status: 201, body: body.to_string() };
            }
            match c.url.strip_prefix(&format!("https://api.github.com/repos/{now}/")) {
                Some(rest) => repo.github(&HttpCall { url: format!("https://api.github.com/repos/acme/docs/{rest}"), ..c.clone() }),
                None => HttpReply { status: 404, body: "{}".into() },
            }
        };
        let sync = || filled(drive(&h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin)), &github).0);
        let content = |path: &str| post(&h, &doc_ids(&h)[path], &admin)["content"].as_str().unwrap().to_string();
        assert_eq!((sync()["created"].as_i64(), sync()["created"].as_i64()), (Some(20), Some(1)));
        let last = doc_ids(&h)["zz.md"].clone();

        // Renamed: the first run renders 20 files again; zz.md is still owed one.
        *name.borrow_mut() = "acme/handbook";
        let r = sync();
        assert_eq!((r["updated"].as_i64(), r["remaining"].as_i64()), (Some(20), Some(1)), "{r}");
        assert!(content("zz.md").contains("acme/docs/blob"), "not rendered yet");
        // zz.md moves, unchanged, before the next run: it's found by its last synced contents and
        // keeps its post (comments, history and links), then is rendered under the new name.
        repo.put("moved/zz.md", &repo.remove("zz.md"));
        let r = sync();
        assert_eq!((r["renamed"].as_i64(), r["archived"].as_i64(), r["created"].as_i64()), (Some(1), Some(0), Some(0)), "{r}");
        assert_eq!(doc_ids(&h)["moved/zz.md"], last);
        // (One folder deeper now, its link points elsewhere in the repository.)
        let moved = content("moved/zz.md");
        assert!(moved.contains("[the API](https://github.com/acme/handbook/blob/main/handbook/api/README.md)"), "{moved}");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_rerender"), 0, "nothing owed");
        assert_eq!(sync()["unchanged"], 21);
    }

    #[test]
    fn sync_now_on_a_disconnected_source_asks_github_again() {
        let (h, admin, source) = github_with_a_source();
        let gh = GitHubNow::new();
        let answer = |c: &HttpCall| gh.answer(c);
        let change = json!({ "action": "removed", "installation": { "id": 42 }, "repositories_removed": [] });
        // Sync now on a disconnected source: nothing syncs, it says it's checking, and any check it
        // starts comes with its answer.
        let sync_now = || {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            assert_eq!(r.status, 200, "{}", r.body);
            assert!(r.body["checking"].as_str().unwrap().contains("checking"), "{}", r.body);
            background(&r)
        };
        // Out of reach: disconnected.
        gh.repos.borrow_mut().retain(|(id, _)| *id != 7);
        check(&h, "installation_repositories", &change, &gh);
        assert!(source_of(&h, &admin)["disconnected"].is_string());
        // No check owed: Sync now asks for one, which finds it still out of reach.
        let (asked, _) = gens(&h);
        let checks = sync_now();
        assert_eq!((checks.len(), gens(&h).0), (1, asked + 1));
        assert_eq!(filled(drive(&h, checks[0].clone(), &answer).0)["state"], "active");
        assert!(source_of(&h, &admin)["disconnected"].is_string());
        // Access comes back, but the check of it fails (GitHub is down) and waits a while.
        gh.repos.borrow_mut().push((7, "acme/docs"));
        *gh.down.borrow_mut() = true;
        let failing = check_of(&h, "installation_repositories", &change);
        assert!(matches!(drive(&h, failing, &answer).0, Finish::Fail(_)));
        *gh.down.borrow_mut() = false;
        // While that check is owed and waiting, Sync now neither asks for another nor skips the
        // wait, however often it's clicked.
        let owed = gens(&h);
        for _ in 0..3 {
            assert!(sync_now().is_empty());
        }
        assert_eq!(gens(&h), owed);
        // Once the wait is over, Sync now runs the owed check (still asking for no other), and a
        // second click meanwhile starts nothing. The check reconnects the source.
        db_run(&h, |db| db.execute("UPDATE github_installations SET next_check_at = '2000-01-01T00:00:00.000Z'", &[]));
        let checks = sync_now();
        assert_eq!((checks.len(), gens(&h)), (1, owed));
        assert!(sync_now().is_empty());
        assert_eq!(gens(&h), owed);
        assert_eq!(filled(drive(&h, checks[0].clone(), &answer).0)["state"], "active");
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null);
        assert_eq!(gens(&h), (owed.0, owed.0), "nothing owed");
    }

    #[test]
    fn redelivered_installation_events_follow_githubs_current_state() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_app(&mut h);
        connect_github(&h, &admin, "&installation_id=42&setup_action=install", &installer);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Handbook" })), &admin)["id"].as_str().unwrap().to_string();
        let input = json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "topic_id": topic });
        h.ok("POST", "/api/v1/docs-sources", Some(input), &admin);
        let gh = GitHubNow::new();
        let lifecycle = |action: &str| json!({ "action": action, "installation": { "id": 42, "account": { "login": "acme" } } });
        let suspended = |h: &H| h.ok("GET", "/api/v1/docs-sources/github", None, &admin)["installations"][0]["suspended"].clone();

        // A suspension didn't reach this workspace (the delivery failed here); the unsuspension did.
        // An operator then redelivers the failed suspension: GitHub says the installation is active,
        // so it stays active.
        check(&h, "installation", &lifecycle("unsuspend"), &gh);
        assert_eq!(check(&h, "installation", &lifecycle("suspend"), &gh).0["state"], "active");
        assert_eq!((suspended(&h), source_of(&h, &admin)["disconnected"].clone()), (json!(false), Value::Null));

        // The other way round: suspended now, and an old unsuspension redelivered keeps it so.
        *gh.state.borrow_mut() = "suspended";
        check(&h, "installation", &lifecycle("suspend"), &gh);
        assert_eq!(check(&h, "installation", &lifecycle("unsuspend"), &gh).0["state"], "suspended");
        assert_eq!(suspended(&h), json!(true));
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("suspended"));

        // A redelivered uninstall while the installation still exists changes nothing.
        *gh.state.borrow_mut() = "active";
        assert_eq!(check(&h, "installation", &lifecycle("deleted"), &gh).0["state"], "active");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM github_installations"), 1);
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null);
    }

    #[test]
    fn github_app_routes_need_the_app() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        let body = json!({ "installation": { "id": 42 } }).to_string();
        assert_eq!(hook(&h, "/hooks/github", &body, &[("x-github-event", "push")]).status, 404, "no App, no webhook");
        assert!(location(&callback(&h, &admin, "state=x&code=c")).ends_with("connect_error=expired_link&app=github"));
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Docs" })), &admin)["id"].clone();
        let input = json!({ "provider": "github", "installation_id": 42, "repository": "acme/docs", "topic_id": topic });
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input), &admin).status, 503);
        let repos = h.ok("GET", "/api/v1/docs-sources/github", None, &admin);
        assert_eq!((repos["available"].as_bool(), repos["connect_url"].clone()), (Some(false), Value::Null));
        assert_eq!(h.call("GET", "/sync/github/other", None, &admin).status, 404);
    }

    // -----------------------------------------------------------------------
    // Docs through DumbSlab's GitLab app

    /// gitlab.com, for an admin who maintains `acme/handbook` (id 3). Each approval is a grant: an
    /// access token `glo_<n>` and a refresh token `glr_<n>`, and a refresh replaces both, as GitLab
    /// does. Webhooks are kept as GitLab would.
    struct GitLabCom {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        /// Live grants: refresh token → access token.
        grants: RefCell<BTreeMap<String, String>>,
        issued: RefCell<u32>,
        /// Access tokens that can no longer read the project (their person lost access).
        blocked: RefCell<BTreeSet<String>>,
        hooks: RefCell<BTreeMap<i64, Value>>,
        next_hook: RefCell<i64>,
        removed: RefCell<Vec<String>>,
        /// Project 3's path now (renamed or moved, it changes).
        path: RefCell<String>,
        /// Another project (4) that took project 3's first path, `acme/handbook`, with its own files.
        squatter: RefCell<Option<BTreeMap<String, Vec<u8>>>>,
        /// GitLab can't answer just now (5xx).
        down: RefCell<bool>,
    }

    impl GitLabCom {
        fn new(files: &[(&str, &[u8])]) -> GitLabCom {
            GitLabCom {
                files: RefCell::new(files.iter().map(|(p, b)| (p.to_string(), b.to_vec())).collect()),
                grants: RefCell::new(BTreeMap::new()),
                issued: RefCell::new(0),
                blocked: RefCell::new(BTreeSet::new()),
                hooks: RefCell::new(BTreeMap::new()),
                next_hook: RefCell::new(9),
                removed: RefCell::new(vec![]),
                path: RefCell::new("acme/handbook".into()),
                squatter: RefCell::new(None),
                down: RefCell::new(false),
            }
        }

        fn grant(&self) -> HttpReply {
            *self.issued.borrow_mut() += 1;
            let n = *self.issued.borrow();
            self.grants.borrow_mut().insert(format!("glr_{n}"), format!("glo_{n}"));
            ok(
                json!({ "access_token": format!("glo_{n}"), "refresh_token": format!("glr_{n}"), "expires_in": 7200, "token_type": "Bearer" }),
            )
        }

        fn hook_token(&self, id: i64) -> String {
            self.hooks.borrow()[&id]["token"].as_str().unwrap().to_string()
        }

        /// A project's files: its tree and blobs, `rest` coming after `/repository`.
        fn repository(rest: &str, files: &BTreeMap<String, Vec<u8>>) -> HttpReply {
            if rest.starts_with("/tree?ref=main&recursive=true&per_page=100&page=") {
                let entries: Vec<Value> = files
                    .iter()
                    .map(|(p, b)| json!({ "id": sha(b), "name": p.rsplit('/').next(), "type": "blob", "path": p, "mode": "100644" }))
                    .collect();
                return ok(if rest.contains("&page=1&") { json!(entries) } else { json!([]) });
            }
            if let Some(blob) = rest.strip_prefix("/blobs/")
                && let Some(b) = files.values().find(|b| sha(b) == blob)
            {
                return ok(json!({ "content": base64::engine::general_purpose::STANDARD.encode(b), "encoding": "base64" }));
            }
            HttpReply { status: 404, body: "{}".into() }
        }

        fn answer(&self, c: &HttpCall) -> HttpReply {
            if *self.down.borrow() {
                return HttpReply { status: 503, body: "{}".into() };
            }
            let form = c.body.clone().unwrap_or_default();
            if c.url == "https://gitlab.com/oauth/token" {
                assert!(form.contains("client_id=gl-client") && form.contains("client_secret=gl-secret"), "{form}");
                if form.contains("grant_type=authorization_code") {
                    assert!(
                        form.contains("code_verifier=") && form.contains("redirect_uri=https%3A%2F%2Fkb.test%2Fsync%2Fgitlab%2Fcallback"),
                        "{form}"
                    );
                    return self.grant();
                }
                let refresh = form.split('&').find_map(|kv| kv.strip_prefix("refresh_token=")).unwrap_or_default().to_string();
                if self.grants.borrow_mut().remove(&refresh).is_some() {
                    return self.grant();
                }
                return HttpReply { status: 400, body: json!({ "error": "invalid_grant" }).to_string() };
            }
            let token = c.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.trim_start_matches("Bearer ").to_string());
            let Some(token) = token.filter(|t| self.grants.borrow().values().any(|v| v == t)) else {
                return HttpReply { status: 401, body: "{}".into() };
            };
            let api = "https://gitlab.com/api/v4";
            if c.url == format!("{api}/user") {
                return ok(json!({ "username": "ada" }));
            }
            if c.url.starts_with(&format!("{api}/projects?membership=true&min_access_level=40")) {
                return ok(if c.url.ends_with("&page=1") {
                    json!([{ "id": 3, "path_with_namespace": "acme/handbook", "default_branch": "main", "visibility": "private" }])
                } else {
                    json!([])
                });
            }
            let readable = !self.blocked.borrow().contains(&token);
            let path = self.path.borrow().clone();
            let squatted = self.squatter.borrow().is_some();
            if squatted && c.url == format!("{api}/projects/acme%2Fhandbook") {
                return ok(json!({ "id": 4, "path_with_namespace": "acme/handbook", "default_branch": "main" }));
            }
            if c.url == format!("{api}/projects/3") || c.url == format!("{api}/projects/{}", urlencoding::encode(&path)) {
                return if readable {
                    ok(json!({ "id": 3, "path_with_namespace": path, "default_branch": "main" }))
                } else {
                    HttpReply { status: 404, body: "{}".into() }
                };
            }
            if let Some(rest) = c.url.strip_prefix(&format!("{api}/projects/3/hooks")) {
                if !readable {
                    return HttpReply { status: 403, body: "{}".into() };
                }
                if c.method == "GET" && rest.starts_with("?per_page=100&page=") {
                    let first = rest.ends_with("page=1");
                    let all: Vec<Value> = self.hooks.borrow().iter().map(|(id, h)| json!({ "id": id, "url": h["url"] })).collect();
                    return ok(if first { json!(all) } else { json!([]) });
                }
                let id: Option<i64> = rest.strip_prefix('/').and_then(|i| i.parse().ok());
                return match (c.method, id) {
                    ("POST", None) => {
                        let id = *self.next_hook.borrow();
                        *self.next_hook.borrow_mut() += 1;
                        self.hooks.borrow_mut().insert(id, serde_json::from_str(&form).unwrap());
                        HttpReply { status: 201, body: json!({ "id": id }).to_string() }
                    }
                    ("PUT", Some(id)) if self.hooks.borrow().contains_key(&id) => {
                        self.hooks.borrow_mut().insert(id, serde_json::from_str(&form).unwrap());
                        ok(json!({ "id": id }))
                    }
                    ("DELETE", Some(id)) => {
                        self.removed.borrow_mut().push(c.url.clone());
                        self.hooks.borrow_mut().remove(&id);
                        HttpReply { status: 204, body: String::new() }
                    }
                    _ => HttpReply { status: 404, body: "{}".into() },
                };
            }
            // Project 3's files, by its id; by path, whichever project has that path now.
            if let Some(rest) = c.url.strip_prefix(&format!("{api}/projects/3/repository")) {
                return if readable { Self::repository(rest, &self.files.borrow()) } else { HttpReply { status: 404, body: "{}".into() } };
            }
            if let Some(rest) = c.url.strip_prefix(&format!("{api}/projects/acme%2Fhandbook/repository"))
                && let Some(files) = self.squatter.borrow().as_ref()
            {
                return Self::repository(rest, files);
            }
            assert!(!c.url.contains("/repository/"), "a GitLab app folder reads its project by id: {c:?}");
            HttpReply { status: 404, body: "{}".into() }
        }
    }

    fn with_gitlab_app(h: &mut H) {
        h.cfg
            .connectors
            .apps
            .insert("gitlab".into(), connect::OAuthApp { client_id: "gl-client".into(), client_secret: "gl-secret".into() });
    }

    /// Connect GitLab in `who`'s browser session, all the way.
    fn connect_gitlab(h: &H, who: &Auth, lab: &GitLabCom) {
        let to = location(&h.raw("GET", "/sync/gitlab/start", vec![], "", who));
        assert!(
            to.starts_with(
                "https://gitlab.com/oauth/authorize?client_id=gl-client&redirect_uri=https%3A%2F%2Fkb.test%2Fsync%2Fgitlab%2Fcallback"
            ),
            "{to}"
        );
        assert!(to.contains("&scope=api&") && to.contains("code_challenge_method=S256"), "{to}");
        let state = to.split("&state=").nth(1).unwrap().split('&').next().unwrap().to_string();
        let r = h.raw("GET", &format!("/sync/gitlab/callback?state={state}&code=gl-code"), vec![], "", who);
        assert_eq!(redirect_of(drive(h, job_of(&r), &|c| lab.answer(c)).0), "https://kb.test/settings/docs-sync?connected=gitlab");
    }

    /// Runs a job like a host: each step in its own transaction, a step the guard refuses rolled
    /// back (as the Worker refuses one that grows a full workspace), and `before` called ahead of
    /// each step. Returns how it ended, the notice the host would send, its effects and requests.
    fn run_job(
        h: &H,
        mut job: Job,
        answer: &dyn Fn(&HttpCall) -> HttpReply,
        before: &dyn Fn(usize),
        refuse: &dyn Fn(usize) -> bool,
    ) -> (Result<Finish, dumbslab_core::ApiError>, Option<HttpCall>, Vec<Effect>, Vec<HttpCall>) {
        let mut replies = vec![];
        let mut sent = vec![];
        for n in 0..connect::MAX_STEPS {
            before(n);
            let (step, notice, next) = h
                .store
                .with_tx(|db| {
                    let full = || dumbslab_core::ApiError::new(507, "storage_full", "the workspace is full");
                    let (step, notice) =
                        connect::guarded_step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now(), |_| refuse(n).then(full));
                    let ok = step.is_ok();
                    ((step, notice, job.clone()), ok)
                })
                .unwrap();
            job = next;
            match step {
                Err(e) => return (Err(e), notice, job.take_effects(), sent),
                Ok(Step::Done(f)) => return (Ok(f), None, job.take_effects(), sent),
                Ok(Step::Fetch(calls)) => {
                    replies = calls.iter().map(answer).collect();
                    sent.extend(calls);
                }
            }
        }
        panic!("the job took more steps than a host allows");
    }

    fn no_op(_: usize) {}

    fn never(_: usize) -> bool {
        false
    }

    /// Adds a GitLab app folder (after Connect GitLab): its id and its webhook's id.
    fn add_gitlab_folder(h: &H, admin: &Auth, lab: &GitLabCom, topic: &str, folder: &str) -> (String, i64) {
        connect_gitlab(h, admin, lab);
        let input =
            json!({ "provider": "gitlab", "repository": "acme/handbook", "folder": folder, "topic_id": topic, "gitlab_connection": true });
        let r = h.call("POST", "/api/v1/docs-sources", Some(input), admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let created = filled(drive(h, job_of(&r), &|c| lab.answer(c)).0);
        let hook = *lab.hooks.borrow().keys().last().unwrap();
        (created["source"]["id"].as_str().unwrap().to_string(), hook)
    }

    fn gitlab_setup() -> (H, Auth, GitLabCom, String) {
        let mut h = H::new();
        let (admin, _) = h.setup();
        with_key(&mut h);
        with_gitlab_app(&mut h);
        let lab = GitLabCom::new(&[("docs/README.md", b"# Runbooks\n\nStart here.\n"), ("docs/deploy.md", b"# Deploy\n")]);
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Runbooks" })), &admin)["id"].as_str().unwrap().to_string();
        (h, admin, lab, topic)
    }

    #[test]
    fn gitlab_app_adds_its_own_webhook_and_refreshes_its_tokens() {
        let mut h = H::new();
        let (admin, _) = h.setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let mo_cookie = sign_in(&h, "mo@acme.test", "password123");
        with_key(&mut h);
        assert_eq!(h.ok("GET", "/api/v1/docs-sources", None, &admin)["gitlab_app"], false);
        assert!(location(&h.raw("GET", "/sync/gitlab/start", vec![], "", &admin)).ends_with("connect_error=unavailable&app=gitlab"));
        with_gitlab_app(&mut h);
        assert_eq!(h.ok("GET", "/api/v1/docs-sources", None, &admin)["gitlab_app"], true);
        let lab = GitLabCom::new(&[("docs/README.md", b"# Runbooks\n\nStart here.\n"), ("docs/deploy.md", b"# Deploy\n")]);
        let answer = |c: &HttpCall| lab.answer(c);

        // Not connected yet: nothing to list, and nothing to add a folder with.
        let none = h.ok("GET", "/api/v1/docs-sources/gitlab", None, &admin);
        assert_eq!((none["connected"].as_bool(), none["connect_url"].as_str()), (Some(false), Some("https://kb.test/sync/gitlab/start")));
        assert!(location(&h.raw("GET", "/sync/gitlab/start", vec![], "", &mo_cookie)).ends_with("connect_error=not_admin&app=gitlab"));

        connect_gitlab(&h, &admin, &lab);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_connections WHERE secret LIKE '%glo_%' OR secret LIKE '%glr_%'"), 0, "sealed");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM activity WHERE event = 'gitlab.connected'"), 1);
        let r = h.call("GET", "/api/v1/docs-sources/gitlab", None, &admin);
        let listed = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!((listed["account"].as_str(), listed["projects"][0]["path"].as_str()), (Some("@ada"), Some("acme/handbook")), "{listed}");
        assert_eq!(h.call("GET", "/api/v1/docs-sources/gitlab", None, &mo).status, 403);

        // Adding a folder: DumbSlab adds the project's webhook with the source's own secret.
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Runbooks" })), &admin)["id"].as_str().unwrap().to_string();
        let input =
            json!({ "provider": "gitlab", "repository": "acme/handbook", "folder": "docs", "topic_id": topic, "gitlab_connection": true });
        let refused = |change: Value| {
            let mut i = input.clone();
            i.as_object_mut().unwrap().extend(change.as_object().unwrap().clone());
            h.call("POST", "/api/v1/docs-sources", Some(i), &admin).status
        };
        assert_eq!(refused(json!({ "token": "glpat-x" })), 400);
        assert_eq!(refused(json!({ "host": "https://git.acme.test" })), 400, "self-managed GitLab takes a token");
        assert_eq!(refused(json!({ "provider": "github" })), 400);
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(input.clone()), &mo).status, 403);
        let r = h.call("POST", "/api/v1/docs-sources", Some(input.clone()), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let created = filled(drive(&h, job_of(&r), &answer).0);
        let source = created["source"]["id"].as_str().unwrap().to_string();
        assert_eq!((created["source"]["connection"].as_str(), created["source"]["branch"].as_str()), (Some("gitlab_oauth"), Some("main")));
        assert_eq!(created["webhook_secret"], Value::Null, "nothing to add by hand");
        assert_eq!(created["source"]["webhook_url"], format!("https://kb.test/hooks/docs/{source}"), "where DumbSlab pointed it");
        let hook_body = lab.hooks.borrow()[&9].clone();
        assert_eq!(
            (hook_body["url"].as_str(), hook_body["push_events"].as_bool()),
            (Some(format!("https://kb.test/hooks/docs/{source}").as_str()), Some(true))
        );
        let secret = lab.hook_token(9);
        assert!(secret.starts_with("whsec_"));
        assert!(!h.ok("GET", "/api/v1/docs-sources", None, &admin).to_string().contains(&secret), "the secret never comes back");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_connections"), 0, "the approval moved to the source");
        let again = h.call(
            "POST",
            "/api/v1/docs-sources",
            Some(json!({ "provider": "gitlab", "repository": "acme/handbook", "topic_id": topic, "gitlab_connection": true })),
            &admin,
        );
        assert_eq!(again.status, 409, "connect again for another folder");

        // Syncs read with the source's own token, and pushes arrive through the webhook it added.
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        assert_eq!(filled(drive(&h, job_of(&r), &answer).0)["created"], 2);
        let push = json!({ "object_kind": "push", "ref": "refs/heads/main" }).to_string();
        let r = hook(&h, &format!("/hooks/docs/{source}"), &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", &secret)]);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(filled(drive(&h, job_of(&r), &answer).0)["unchanged"], 2);
        assert_eq!(
            hook(&h, &format!("/hooks/docs/{source}"), &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", "nope")]).status,
            401
        );

        // A token about to expire is refreshed first, and the new ones are kept (GitLab has
        // replaced the old ones).
        let expire = || db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        expire();
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert_eq!(sent[0].url, "https://gitlab.com/oauth/token");
        assert!(sent[1].headers.contains(&("authorization".into(), "Bearer glo_2".into())), "listed with the new token");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (_, sent) = drive(&h, job_of(&r), &answer);
        assert!(sent.iter().all(|c| c.url != "https://gitlab.com/oauth/token"), "fresh now");

        // Access revoked on GitLab: the folder waits, and Reconnect with a new approval fixes it.
        lab.grants.borrow_mut().clear();
        expire();
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let (finish, _) = drive(&h, job_of(&r), &answer);
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("Connect GitLab again")), "{finish:?}");
        assert!(source_of(&h, &admin)["disconnected"].as_str().unwrap().contains("Reconnect"));
        assert_eq!(h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin).status, 409);
        assert_eq!(
            h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "gitlab_connection": true })), &admin).status,
            409,
            "connect first"
        );
        connect_gitlab(&h, &admin, &lab);
        let r = h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "gitlab_connection": true })), &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(source_of(&h, &admin)["disconnected"], Value::Null);
        assert_eq!(lab.hook_token(9), secret, "the webhook kept its secret");
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        filled(drive(&h, job_of(&r), &answer).0);
        let r = hook(&h, &format!("/hooks/docs/{source}"), &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", &secret)]);
        assert_eq!(r.status, 200);
        drive(&h, job_of(&r), &answer);

        // Removing the source takes the webhook off the project.
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        assert_eq!(r.status, 200);
        let jobs = background(&r);
        assert_eq!(jobs.len(), 1);
        filled(drive(&h, jobs[0].clone(), &answer).0);
        assert_eq!(lab.removed.borrow().as_slice(), ["https://gitlab.com/api/v4/projects/3/hooks/9"]);
        assert!(lab.hooks.borrow().is_empty());
    }

    #[test]
    fn a_gitlab_approval_serves_one_request_at_a_time() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        connect_gitlab(&h, &admin, &lab);
        let folder = |name: &str| json!({ "provider": "gitlab", "repository": "acme/handbook", "folder": name, "topic_id": topic, "gitlab_connection": true });

        // Two folders at once: the first holds the approval until it's saved with it; the second is
        // refused, so the approval never ends up in two folders.
        let first = h.call("POST", "/api/v1/docs-sources", Some(folder("docs")), &admin);
        assert_eq!(first.status, 200);
        let second = h.call("POST", "/api/v1/docs-sources", Some(folder("guides")), &admin);
        assert_eq!(second.status, 409, "{}", second.body);
        assert!(second.body["error"]["message"].as_str().unwrap().contains("in use"));
        assert_eq!(h.call("GET", "/api/v1/docs-sources/gitlab", None, &admin).status, 409, "listing waits too");
        filled(drive(&h, job_of(&first), &answer).0);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources"), 1);
        assert_eq!(h.call("POST", "/api/v1/docs-sources", Some(folder("guides")), &admin).status, 409, "used up: connect again");

        // Listing while the approval's token expires: only the request holding it refreshes it.
        connect_gitlab(&h, &admin, &lab);
        db_run(&h, |db| db.execute("UPDATE docs_connections SET expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let listing = h.call("GET", "/api/v1/docs-sources/gitlab", None, &admin);
        assert_eq!(h.call("GET", "/api/v1/docs-sources/gitlab", None, &admin).status, 409);
        let (finish, sent) = drive(&h, job_of(&listing), &answer);
        assert_eq!(filled(finish)["projects"][0]["path"], "acme/handbook");
        assert_eq!(sent[0].url, "https://gitlab.com/oauth/token");
        // The refreshed approval was kept and let go: the next request uses it without refreshing.
        let r = h.call("GET", "/api/v1/docs-sources/gitlab", None, &admin);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        filled(finish);
        assert!(sent.iter().all(|c| c.url != "https://gitlab.com/oauth/token"));

        // Connecting again while a folder is being added replaces the approval it holds: the folder
        // isn't saved, and the webhook it added comes off again.
        let r = h.call("POST", "/api/v1/docs-sources", Some(folder("guides")), &admin);
        let replace = |n: usize| {
            if n == 2 {
                connect_gitlab(&h, &admin, &lab);
            }
        };
        let (result, notice, _, _) = run_job(&h, job_of(&r), &answer, &replace, &never);
        assert!(matches!(&result, Err(e) if e.status == 409), "{result:?}");
        let notice = notice.expect("the new webhook comes off");
        assert_eq!((notice.method, notice.url.as_str()), ("DELETE", "https://gitlab.com/api/v4/projects/3/hooks/10"));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources"), 1, "not saved");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_connections WHERE claimed_until IS NULL"), 1, "the new approval is free");
    }

    #[test]
    fn gitlab_webhooks_come_off_however_their_folder_goes() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");

        // Removing a folder while its sync is refreshing the token: refused until the sync has
        // saved the new tokens, so the removal uses those, not ones GitLab has replaced.
        db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let sync = job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin));
        let midway = |n: usize| {
            if n == 1 {
                let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
                assert_eq!(r.status, 409, "between the refresh and its answer: {}", r.body);
            }
        };
        let (result, _, _, sent) = run_job(&h, sync, &answer, &midway, &never);
        assert!(matches!(result, Ok(Finish::Fill(_))), "{result:?}");
        assert_eq!(sent[0].url, "https://gitlab.com/oauth/token");
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, background(&r)[0].clone(), &answer).0);
        assert_eq!(
            lab.removed.borrow().as_slice(),
            [format!("https://gitlab.com/api/v4/projects/3/hooks/{hook_id}")],
            "with the refreshed token"
        );

        // Deleting the topic removes its folders' webhooks too.
        let (_, first) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let (_, second) = add_gitlab_folder(&h, &admin, &lab, &topic, "guides");
        let r = h.call("DELETE", &format!("/api/v1/topics/{topic}"), None, &admin);
        assert_eq!(r.status, 200, "{}", r.body);
        let jobs = background(&r);
        assert_eq!(jobs.len(), 2);
        for j in jobs {
            filled(drive(&h, j, &answer).0);
        }
        assert!(!lab.hooks.borrow().contains_key(&first) && !lab.hooks.borrow().contains_key(&second));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources"), 0);

        // A folder whose save the host rolls back (the workspace is full): its new webhook comes
        // off again through the failure notice, and the approval waits to be tried again.
        let topic = h.ok("POST", "/api/v1/topics", Some(json!({ "name": "Again" })), &admin)["id"].as_str().unwrap().to_string();
        connect_gitlab(&h, &admin, &lab);
        let input = json!({ "provider": "gitlab", "repository": "acme/handbook", "topic_id": topic, "gitlab_connection": true });
        let r = h.call("POST", "/api/v1/docs-sources", Some(input), &admin);
        let (result, notice, _, _) = run_job(&h, job_of(&r), &answer, &no_op, &|n| n == 2);
        assert!(matches!(&result, Err(e) if e.code == "storage_full"), "{result:?}");
        let notice = notice.expect("a notice");
        let added = *lab.hooks.borrow().keys().last().unwrap();
        assert_eq!((notice.method, notice.url), ("DELETE", format!("https://gitlab.com/api/v4/projects/3/hooks/{added}")));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources"), 0, "rolled back");
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_connections"), 1);
    }

    #[test]
    fn reconnecting_a_gitlab_folder_puts_its_webhook_right() {
        let (mut h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let push = json!({ "object_kind": "push", "ref": "refs/heads/main" }).to_string();
        let deliver = |h: &H, token: &str| {
            hook(h, &format!("/hooks/docs/{source}"), &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", token)])
        };
        let sync = |h: &H| drive(h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin)), &answer).0;

        // The person who approved it loses access to the project, though GitLab still refreshes
        // their tokens: the sync fails, and another maintainer reconnects it.
        let ada_token = format!("glo_{}", lab.issued.borrow());
        lab.blocked.borrow_mut().insert(ada_token);
        assert!(matches!(sync(&h), Finish::Fail(_)));
        let s = source_of(&h, &admin);
        assert_eq!((s["last_status"].as_str(), s["disconnected"].clone()), (Some("failed"), Value::Null), "not a refused refresh");
        h.user(&admin, "bo@acme.test", "Bo", "admin");
        let bo = sign_in(&h, "bo@acme.test", "password123");
        connect_gitlab(&h, &bo, &lab);
        let r = h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "gitlab_connection": true })), &bo);
        let fixed = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(fixed["source"]["id"], source.as_str());
        assert!(matches!(sync(&h), Finish::Fill(_)), "Bo's approval reads the project");
        let secret = lab.hook_token(hook_id);
        let r = deliver(&h, &secret);
        assert_eq!(r.status, 200);
        filled(drive(&h, job_of(&r), &answer).0);

        // The server's connector key changes: the folder's secret can't be read, so reconnecting
        // gives its webhook a new one on GitLab too, and pushes check out again.
        h.cfg.connectors.key = Some("another-connector-key".into());
        let s = source_of(&h, &admin);
        assert!(s["last_error"].as_str().unwrap().contains("Reconnect"), "{s}");
        assert_eq!(h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "branch": "main" })), &admin).status, 409);
        connect_gitlab(&h, &admin, &lab);
        let r = h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "gitlab_connection": true })), &admin);
        filled(drive(&h, job_of(&r), &answer).0);
        let renewed = lab.hook_token(hook_id);
        assert_ne!(renewed, secret, "a new secret");
        assert_eq!(deliver(&h, &secret).status, 401);
        let r = deliver(&h, &renewed);
        assert_eq!(r.status, 200, "{}", r.body);
        filled(drive(&h, job_of(&r), &answer).0);

        // A webhook someone deleted on GitLab is added again on reconnecting.
        lab.hooks.borrow_mut().clear();
        connect_gitlab(&h, &admin, &lab);
        let r = h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "gitlab_connection": true })), &admin);
        filled(drive(&h, job_of(&r), &answer).0);
        let (&new_hook, body) = lab.hooks.borrow().iter().next().map(|(k, v)| (k, v.clone())).unwrap();
        assert_eq!(body["token"].as_str(), Some(renewed.as_str()));
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        filled(drive(&h, background(&r)[0].clone(), &answer).0);
        assert!(lab.removed.borrow().last().unwrap().ends_with(&format!("/hooks/{new_hook}")), "the stored webhook is the new one");
    }

    /// How a host's transaction for a step can fail.
    #[derive(Clone, Copy)]
    enum Broken {
        /// It can't start: the step never runs.
        Start,
        /// It can't commit: the step runs and is rolled back.
        Commit,
    }

    /// Runs a job like a host whose transaction for step `n` fails. The host then sends the notice
    /// it worked out before that step (see `connect::unran_notice`), which this returns.
    fn run_broken(h: &H, mut job: Job, answer: &dyn Fn(&HttpCall) -> HttpReply, n: usize, how: Broken) -> Option<HttpCall> {
        let mut replies = vec![];
        for i in 0..connect::MAX_STEPS {
            let unran = connect::unran_notice(&mut job, &replies);
            if i == n {
                if let Broken::Commit = how {
                    h.store
                        .with_tx(|db| {
                            let (step, _) = connect::guarded_step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now(), |_| None);
                            assert!(step.is_ok(), "the step itself works; only its commit fails");
                            ((), false)
                        })
                        .unwrap();
                }
                return unran;
            }
            let (step, next) = h
                .store
                .with_tx(|db| {
                    let (step, _) = connect::guarded_step(db, &h.cfg, &mut job, replies.clone(), chrono::Utc::now(), |_| None);
                    let ok = step.is_ok();
                    ((step, job.clone()), ok)
                })
                .unwrap();
            job = next;
            match step.unwrap() {
                Step::Fetch(calls) => replies = calls.iter().map(answer).collect(),
                Step::Done(f) => panic!("the job finished before step {n}: {f:?}"),
            }
        }
        panic!("the job took more steps than a host allows");
    }

    #[test]
    fn a_new_gitlab_webhook_comes_off_when_its_save_never_commits() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let newest = || *lab.hooks.borrow().keys().last().unwrap();
        let removes = |notice: Option<HttpCall>, hook: i64| {
            let n = notice.expect("a notice");
            assert_eq!((n.method, n.url), ("DELETE", format!("https://gitlab.com/api/v4/projects/3/hooks/{hook}")));
        };

        // Adding a folder: the step that saves it (the third) can't start, or can't commit.
        for how in [Broken::Start, Broken::Commit] {
            connect_gitlab(&h, &admin, &lab);
            let input = json!({ "provider": "gitlab", "repository": "acme/handbook", "topic_id": topic, "gitlab_connection": true });
            let r = h.call("POST", "/api/v1/docs-sources", Some(input), &admin);
            let notice = run_broken(&h, job_of(&r), &answer, 2, how);
            removes(notice, newest());
            assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_sources"), 0);
        }

        // Reconnecting a folder whose webhook someone deleted: the replacement comes off the same way.
        let (source, first) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        for how in [Broken::Start, Broken::Commit] {
            lab.hooks.borrow_mut().clear();
            // The failed attempt's hold on the folder runs out.
            db_run(&h, |db| db.execute("UPDATE docs_sources SET running_until = NULL", &[]));
            connect_gitlab(&h, &admin, &lab);
            let r = h.call("PATCH", &format!("/api/v1/docs-sources/{source}"), Some(json!({ "gitlab_connection": true })), &admin);
            assert_eq!(r.status, 200, "{}", r.body);
            let notice = run_broken(&h, job_of(&r), &answer, 2, how);
            removes(notice, newest());
            let kept = db_run(&h, |db| db.one("SELECT hook_id FROM docs_source_links", &[])).unwrap().i64("hook_id");
            assert_eq!(kept, first, "nothing saved");
        }
    }

    #[test]
    fn gitlab_syncs_keep_their_webhook_pointed_here() {
        let (mut h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let secret = lab.hook_token(hook_id);
        let puts = |sent: &[HttpCall]| sent.iter().filter(|c| c.method == "PUT").count();
        let push = json!({ "object_kind": "push", "ref": "refs/heads/main" }).to_string();
        let pushed = |h: &H| -> (Value, Vec<HttpCall>) {
            let r = hook(h, &format!("/hooks/docs/{source}"), &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", &secret)]);
            assert_eq!(r.status, 200, "{}", r.body);
            let (finish, sent) = drive(h, job_of(&r), &answer);
            (filled(finish), sent)
        };
        let sync_now = |h: &H| -> (Value, Vec<HttpCall>) {
            let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
            let (finish, sent) = drive(h, job_of(&r), &answer);
            (filled(finish), sent)
        };

        // A push leaves a webhook that points here alone; Sync now checks it anyway.
        assert_eq!(puts(&pushed(&h).1), 0);
        let (v, sent) = sync_now(&h);
        assert_eq!((puts(&sent), v["webhook"].as_str()), (1, Some("checked")));

        // The workspace moves (this server knows its address): a push never moves the webhook;
        // Sync now points it at the new address.
        h.cfg.base_url = Some("https://wiki.kb.test".into());
        assert_eq!(puts(&pushed(&h).1), 0, "pushes leave it alone");
        let (v, sent) = sync_now(&h);
        assert_eq!((puts(&sent), v["webhook"].as_str()), (1, Some("pointed at this workspace's address")));
        assert_eq!(lab.hooks.borrow()[&hook_id]["url"], format!("https://wiki.kb.test/hooks/docs/{source}"));
        assert_eq!(lab.hook_token(hook_id), secret, "same secret");
        assert_eq!(source_of(&h, &admin)["webhook_url"], format!("https://wiki.kb.test/hooks/docs/{source}"));

        // Someone deletes it on GitLab: Sync now adds it again, within the same sync, even with an
        // expired token to refresh and files to read.
        lab.hooks.borrow_mut().clear();
        lab.files.borrow_mut().insert("docs/new.md".into(), b"# New\n".to_vec());
        db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let (v, sent) = sync_now(&h);
        assert_eq!((v["webhook"].as_str(), v["created"].as_i64()), (Some("added again"), Some(1)), "{v}");
        assert_eq!(sent[0].url, "https://gitlab.com/oauth/token");
        let (&again, body) = lab.hooks.borrow().iter().next().map(|(k, v)| (k, v.clone())).unwrap();
        assert_eq!(
            (body["url"].as_str(), body["token"].as_str()),
            (Some(format!("https://wiki.kb.test/hooks/docs/{source}").as_str()), Some(secret.as_str()))
        );
        assert_eq!(db_run(&h, |db| db.one("SELECT hook_id FROM docs_source_links", &[])).unwrap().i64("hook_id"), again);
        assert_eq!(pushed(&h).0["unchanged"], 3, "pushes arrive again");

        // And if the step saving the new one never commits, it comes off again.
        lab.hooks.borrow_mut().clear();
        let r = h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let notice = run_broken(&h, job_of(&r), &answer, 2, Broken::Commit).expect("a notice");
        let added = *lab.hooks.borrow().keys().last().unwrap();
        assert_eq!((notice.method, notice.url), ("DELETE", format!("https://gitlab.com/api/v4/projects/3/hooks/{added}")));
    }

    #[test]
    fn a_server_that_doesnt_know_its_address_keeps_the_webhook_where_it_was_set() {
        let (mut h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let set = format!("https://kb.test/hooks/docs/{source}");
        let secret = lab.hook_token(hook_id);
        // Self-hosted without --base-url: the address is whatever Host a request names.
        h.cfg.base_url = None;
        assert!(!h.cfg.knows_its_address());
        let Auth::Cookie(session) = admin.clone() else { panic!("a browser session") };
        let from = |origin: &str, method: &str, path: &str, body: Option<Value>| {
            h.send(&Request {
                method: method.into(),
                path: path.into(),
                query: String::new(),
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("x-dumbslab-client".into(), "web".into()),
                    ("cookie".into(), format!("dumbslab_session={session}")),
                ],
                body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
                origin: origin.into(),
                client_ip: None,
            })
        };

        // Sync now through an unexpected Host (a LAN address, a proxy, DNS rebinding): the webhook
        // is checked where it was set, with its secret, and not pointed anywhere else.
        let r = from("http://192.168.1.20:8080", "POST", &format!("/api/v1/docs-sources/{source}/sync"), None);
        assert_eq!(r.status, 200, "{}", r.body);
        let (finish, sent) = drive(&h, job_of(&r), &answer);
        assert_eq!(filled(finish)["webhook"], "checked");
        assert!(sent.iter().filter(|c| c.method == "PUT").all(|c| c.body.as_deref().unwrap().contains(&set)), "only the address it had");
        assert_eq!((lab.hooks.borrow()[&hook_id]["url"].as_str(), lab.hook_token(hook_id)), (Some(set.as_str()), secret.clone()));

        // Gone on GitLab: added again at the address it had, not the request's.
        lab.hooks.borrow_mut().clear();
        let r = from("http://evil.test", "POST", &format!("/api/v1/docs-sources/{source}/sync"), None);
        assert_eq!(filled(drive(&h, job_of(&r), &answer).0)["webhook"], "added again");
        let (_, body) = lab.hooks.borrow().iter().next().map(|(k, v)| (*k, v.clone())).unwrap();
        assert_eq!(body["url"].as_str(), Some(set.as_str()));

        // Only Reconnect, an admin's choice, moves it, and the answer shows where.
        connect_gitlab(&h, &admin, &lab);
        let r = from(
            "https://wiki.example.test",
            "PATCH",
            &format!("/api/v1/docs-sources/{source}"),
            Some(json!({ "gitlab_connection": true })),
        );
        assert_eq!(r.status, 200, "{}", r.body);
        let moved = filled(drive(&h, job_of(&r), &answer).0);
        assert_eq!(moved["source"]["webhook_url"], format!("https://wiki.example.test/hooks/docs/{source}"));
    }

    #[test]
    fn a_late_sync_never_overwrites_a_newer_webhook_repair() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let newest = || *lab.hooks.borrow().keys().last().unwrap();
        let hooks = || lab.hooks.borrow().keys().copied().collect::<Vec<i64>>();
        let (source, _) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let stored = || db_run(&h, |db| db.one("SELECT hook_id FROM docs_source_links", &[])).unwrap().i64("hook_id");
        let expire_token =
            || db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let expire_lease = || db_run(&h, |db| db.execute("UPDATE docs_sources SET running_until = '2000-01-01T00:00:00.000Z x'", &[]));
        let sync_now = || job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin));
        lab.hooks.borrow_mut().clear();

        // Sync A finds the webhook gone and adds a new one...
        let mut a = sync_now();
        let Ok(Step::Fetch(calls)) = step_with(&h, &mut a, vec![]).0 else { panic!("the listing") };
        let Ok(Step::Fetch(calls)) = step_with(&h, &mut a, calls.iter().map(answer).collect()).0 else {
            panic!("files and the new webhook")
        };
        let a_replies: Vec<HttpReply> = calls.iter().map(answer).collect();
        let a_hook = newest();
        // ...then takes too long. Sync B takes over: it renews the tokens (A's no longer work),
        // repairs the webhook, and removes A's, which points at this folder too.
        expire_lease();
        expire_token();
        let (finish, sent) = drive(&h, sync_now(), &answer);
        let v = filled(finish);
        assert_eq!(sent[0].url, "https://gitlab.com/oauth/token");
        assert!(
            v["webhook"].as_str().unwrap().contains("added again") && v["webhook"].as_str().unwrap().contains("1 other webhook"),
            "{v}"
        );
        let b_hook = newest();
        assert_eq!((hooks(), stored()), (vec![b_hook], b_hook));

        // A resumes: it may not save its webhook over B's, so its step fails, and its own clean-up
        // (with tokens GitLab replaced) is refused; nothing depends on it.
        let (result, notice) = step_with(&h, &mut a, a_replies);
        assert!(result.is_err(), "{result:?}");
        let notice = notice.expect("A tries to take its webhook off");
        assert_eq!(notice.url, format!("https://gitlab.com/api/v4/projects/3/hooks/{a_hook}"));
        assert_eq!(answer(&notice).status, 401, "A's token was replaced");
        assert_eq!((hooks(), stored()), (vec![b_hook], b_hook), "B's kept");

        // A leftover that no sync took off (here, from a sync that lost its lease after a push's
        // sync renewed the tokens): the next Sync now removes it.
        let leftover = {
            let token = format!("glo_{}", lab.issued.borrow());
            let url = format!("https://kb.test/hooks/docs/{source}");
            let add = connect::HttpCall::post_json("https://gitlab.com/api/v4/projects/3/hooks", &json!({ "url": url, "token": "x" }))
                .header("authorization", format!("Bearer {token}"));
            answer(&add);
            newest()
        };
        assert_eq!(hooks(), vec![b_hook, leftover]);
        let (finish, _) = drive(&h, sync_now(), &answer);
        assert!(filled(finish)["webhook"].as_str().unwrap().contains("1 other webhook"));
        assert_eq!(hooks(), vec![b_hook], "only the folder's own");

        // Removing the folder removes every webhook pointing at it, not just the recorded one.
        answer(
            &connect::HttpCall::post_json(
                "https://gitlab.com/api/v4/projects/3/hooks",
                &json!({ "url": format!("https://kb.test/hooks/docs/{source}"), "token": "x" }),
            )
            .header("authorization", format!("Bearer glo_{}", lab.issued.borrow())),
        );
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        assert_eq!(filled(drive(&h, background(&r)[0].clone(), &answer).0)["removed"], 2);
        assert!(hooks().is_empty());
    }

    #[test]
    fn a_moved_gitlab_project_is_still_read_by_its_id() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, _) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        lab.files.borrow_mut().insert("docs/README.md".into(), b"# Runbooks\n\nSee [the code](../src/main.rs).\n".to_vec());
        let sync = || filled(drive(&h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin)), &answer).0);
        let readme = || post(&h, &doc_ids(&h)["README.md"], &admin)["content"].as_str().unwrap().to_string();
        assert_eq!(sync()["created"], 2);
        assert!(readme().contains("[the code](https://gitlab.com/acme/handbook/-/blob/main/src/main.rs)"), "{}", readme());

        // The project moves to acme/manual, and another project takes acme/handbook, with other
        // files. The folder's syncs still read its own project, by id (the fake refuses reads of
        // project 3 by path), and its links follow the new path.
        *lab.path.borrow_mut() = "acme/manual".into();
        *lab.squatter.borrow_mut() = Some(BTreeMap::from([("docs/README.md".to_string(), b"# Not ours\n".to_vec())]));
        let r = sync();
        assert_eq!((r["updated"].as_i64(), r["unchanged"].as_i64(), r["archived"].as_i64()), (Some(1), Some(1), Some(0)), "{r}");
        assert_eq!(source_of(&h, &admin)["repository"], "acme/manual");
        assert!(readme().contains("[the code](https://gitlab.com/acme/manual/-/blob/main/src/main.rs)"), "{}", readme());
        assert!(!readme().contains("Not ours"));
        let synced =
            "SELECT COUNT(*) FROM posts WHERE status = 'published' AND id IN (SELECT target_id FROM docs_items WHERE kind = 'doc')";
        assert_eq!(count(&h, synced), 2, "none archived");
        let push = json!({ "object_kind": "push", "ref": "refs/heads/main" }).to_string();
        let secret = lab.hook_token(9);
        let r = hook(&h, &format!("/hooks/docs/{source}"), &push, &[("x-gitlab-event", "Push Hook"), ("x-gitlab-token", &secret)]);
        assert_eq!(filled(drive(&h, job_of(&r), &answer).0)["unchanged"], 2, "a push reads it by id too");
    }

    #[test]
    fn only_a_folders_own_gitlab_webhooks_are_taken_off() {
        let (mut h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, own) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let add = |url: String| {
            let token = format!("glo_{}", lab.issued.borrow());
            let call = connect::HttpCall::post_json("https://gitlab.com/api/v4/projects/3/hooks", &json!({ "url": url, "token": "x" }))
                .header("authorization", format!("Bearer {token}"));
            answer(&call);
            *lab.hooks.borrow().keys().last().unwrap()
        };
        let hooks = || lab.hooks.borrow().keys().copied().collect::<Vec<i64>>();
        // People's own webhooks that merely end like the folder's: another host (with a path and
        // a query), another host, a path under another one here, and a query.
        let theirs = vec![
            add(format!("https://unrelated.example/custom/hooks/docs/{source}?mode=other")),
            add(format!("https://unrelated.example/hooks/docs/{source}")),
            add(format!("https://kb.test/custom/hooks/docs/{source}")),
            add(format!("https://kb.test/hooks/docs/{source}?mode=other")),
        ];
        let sync_now =
            |h: &H| filled(drive(h, job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin)), &answer).0);

        // A leftover at the folder's own address goes; theirs stay.
        let leftover = add(format!("https://kb.test/hooks/docs/{source}"));
        assert!(sync_now(&h)["webhook"].as_str().unwrap().contains("1 other webhook"));
        assert!(!hooks().contains(&leftover) && hooks().contains(&own));
        assert!(theirs.iter().all(|t| hooks().contains(t)));

        // The workspace moves: a leftover at its old address, which the folder's webhook had, goes
        // too.
        h.cfg.base_url = Some("https://wiki.kb.test".into());
        sync_now(&h);
        let old = add(format!("https://kb.test/hooks/docs/{source}"));
        assert!(sync_now(&h)["webhook"].as_str().unwrap().contains("1 other webhook"));
        assert!(!hooks().contains(&old));
        assert!(theirs.iter().all(|t| hooks().contains(t)));

        // Removing the folder takes off its own and leaves theirs.
        let stale = add(format!("https://KB.test:443/hooks/docs/{source}"));
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        assert_eq!(filled(drive(&h, background(&r)[0].clone(), &answer).0)["removed"], 2);
        let mut left = hooks();
        left.sort_unstable();
        assert_eq!(left, theirs);
        assert!(!left.contains(&stale) && !left.contains(&own));
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_hook_cleanup"), 0);
    }

    #[test]
    fn removing_a_gitlab_folder_waits_for_a_renewal_and_its_cleanup_is_retried() {
        let (h, admin, lab, topic) = gitlab_setup();
        let (_, mo) = h.user(&admin, "mo@acme.test", "Mo", "member");
        let answer = |c: &HttpCall| lab.answer(c);
        let remove = |source: &str| h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        let settings = || background(&h.call("GET", "/api/v1/docs-sources", None, &admin));
        let due = || db_run(&h, |db| db.execute("UPDATE docs_hook_cleanup SET next_attempt_at = '2000-01-01T00:00:00.000Z'", &[]));
        let records = || count(&h, "SELECT COUNT(*) FROM docs_hook_cleanup");

        // A sync asks GitLab to renew the folder's tokens; its lease runs out with the answer on its
        // way. Removing the folder now would keep tokens GitLab is replacing: it waits.
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let mut a = job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin));
        let Ok(Step::Fetch(calls)) = step_with(&h, &mut a, vec![]).0 else { panic!("a refresh") };
        let a_refresh: Vec<HttpReply> = calls.iter().map(answer).collect();
        db_run(&h, |db| db.execute("UPDATE docs_sources SET running_until = '2000-01-01T00:00:00.000Z x'", &[]));
        let r = remove(&source);
        assert_eq!(r.status, 409, "{}", r.body);
        assert!(r.body["error"]["message"].as_str().unwrap().contains("renewing its GitLab access"), "{}", r.body);
        // The answer lands; then the folder goes, and its cleanup uses the new tokens.
        assert!(matches!(step_with(&h, &mut a, a_refresh).0, Ok(Step::Done(Finish::Fail(_)))), "A lost its lease, its tokens kept");
        let r = remove(&source);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(count(&h, "SELECT COUNT(*) FROM docs_hook_cleanup WHERE secret LIKE '%glo_%'"), 0, "sealed");
        let (finish, sent) = drive(&h, background(&r)[0].clone(), &answer);
        assert_eq!(filled(finish)["removed"], 1);
        assert!(sent.iter().all(|c| c.url != "https://gitlab.com/oauth/token"), "fresh tokens");
        assert!(!lab.hooks.borrow().contains_key(&hook_id));
        assert_eq!(records(), 0);

        // GitLab is down when the next folder goes: the record stays, and waits.
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        *lab.down.borrow_mut() = true;
        let r = remove(&source);
        assert!(matches!(drive(&h, background(&r)[0].clone(), &answer).0, Finish::Fail(_)));
        assert_eq!(records(), 1);
        assert!(settings().is_empty(), "waiting");
        // Once the wait is over, loading Settings tries again, and it's done.
        *lab.down.borrow_mut() = false;
        due();
        let jobs = settings();
        assert_eq!(jobs.len(), 1);
        assert_eq!(filled(drive(&h, jobs[0].clone(), &answer).0)["removed"], 1);
        assert!(!lab.hooks.borrow().contains_key(&hook_id));
        assert_eq!(records(), 0);

        // GitLab stops accepting the tokens: the first refusal waits (another renewal's answer
        // may still land), the second gives up, telling admins which webhook to delete.
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        *lab.down.borrow_mut() = true;
        drive(&h, background(&remove(&source))[0].clone(), &answer);
        *lab.down.borrow_mut() = false;
        lab.grants.borrow_mut().clear();
        db_run(&h, |db| db.execute("UPDATE docs_hook_cleanup SET expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        for _ in 0..2 {
            due();
            let jobs = settings();
            assert_eq!(jobs.len(), 1);
            assert!(matches!(drive(&h, jobs[0].clone(), &answer).0, Finish::Fail(_)));
        }
        assert_eq!(records(), 0);
        assert!(lab.hooks.borrow().contains_key(&hook_id), "left for an admin to delete");
        let event =
            db_run(&h, |db| db.one("SELECT summary, audience, data FROM activity WHERE event = 'docs_source.webhook_abandoned'", &[]))
                .expect("an activity entry");
        assert_eq!(event.str("audience"), "admin");
        assert!(
            event.str("summary").contains(&format!("webhook {hook_id} off the GitLab project acme/handbook (id 3)")),
            "{}",
            event.str("summary")
        );
        assert_eq!(serde_json::from_str::<Value>(&event.str("data")).unwrap(), json!({ "project_id": 3, "hook_ids": [hook_id] }));
        assert!(!h.ok("GET", "/api/v1/activity?limit=200", None, &mo).to_string().contains("webhook_abandoned"), "admins only");

        // A record DumbSlab kept trying for 30 days ends the same way.
        connect_gitlab(&h, &admin, &lab);
        let (source, _) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        *lab.down.borrow_mut() = true;
        drive(&h, background(&remove(&source))[0].clone(), &answer);
        *lab.down.borrow_mut() = false;
        db_run(&h, |db| db.execute("UPDATE docs_hook_cleanup SET created_at = '2000-01-01T00:00:00.000Z'", &[]));
        due();
        drive(&h, settings()[0].clone(), &answer);
        assert_eq!(records(), 0);
        assert_eq!(
            count(&h, "SELECT COUNT(*) FROM activity WHERE event = 'docs_source.webhook_abandoned' AND summary LIKE '%tried for 30 days%'"),
            1
        );
    }

    #[test]
    fn a_full_workspace_keeps_renewed_gitlab_tokens() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, hook_id) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let full = |n: usize| n >= 1;
        let renewals = |sent: &[HttpCall]| sent.iter().filter(|c| c.url == "https://gitlab.com/oauth/token").count();
        let sync = || job_of(&h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin));

        // The workspace is full: the host refuses every step after the first. The step that stores
        // the renewed tokens is kept anyway (GitLab spent the old refresh token); the next isn't.
        db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let (result, _, _, sent) = run_job(&h, sync(), &answer, &no_op, &full);
        assert!(result.is_err(), "the listing step is refused: {result:?}");
        assert_eq!(renewals(&sent), 1);
        // With room again, the next sync uses the renewed tokens, without renewing.
        db_run(&h, |db| db.execute("UPDATE docs_sources SET running_until = NULL", &[]));
        let (finish, sent) = drive(&h, sync(), &answer);
        filled(finish);
        assert_eq!(renewals(&sent), 0);
        assert!(sent[0].headers.contains(&("authorization".into(), format!("Bearer glo_{}", lab.issued.borrow()))), "{:?}", sent[0]);

        // The same for a removed folder's webhook cleanup.
        *lab.down.borrow_mut() = true;
        let r = h.call("DELETE", &format!("/api/v1/docs-sources/{source}"), None, &admin);
        drive(&h, background(&r)[0].clone(), &answer);
        *lab.down.borrow_mut() = false;
        db_run(&h, |db| {
            db.execute(
                "UPDATE docs_hook_cleanup SET expires_at = '2020-01-01T00:00:00.000Z', next_attempt_at = '2000-01-01T00:00:00.000Z'",
                &[],
            )
        });
        let pass = || background(&h.call("GET", "/api/v1/docs-sources", None, &admin)).remove(0);
        let (result, _, _, sent) = run_job(&h, pass(), &answer, &no_op, &full);
        assert!(result.is_err() && renewals(&sent) == 1, "{result:?}");
        db_run(&h, |db| db.execute("UPDATE docs_hook_cleanup SET working_until = NULL", &[]));
        let (finish, sent) = drive(&h, pass(), &answer);
        assert_eq!((filled(finish)["removed"].as_i64(), renewals(&sent)), (Some(1), 0));
        assert!(!lab.hooks.borrow().contains_key(&hook_id));
    }

    #[test]
    fn a_refresh_that_lands_late_keeps_its_tokens() {
        let (h, admin, lab, topic) = gitlab_setup();
        let answer = |c: &HttpCall| lab.answer(c);
        let (source, _) = add_gitlab_folder(&h, &admin, &lab, &topic, "docs");
        let expire_token =
            || db_run(&h, |db| db.execute("UPDATE docs_source_links SET token_expires_at = '2020-01-01T00:00:00.000Z'", &[]));
        let expire_lease = || db_run(&h, |db| db.execute("UPDATE docs_sources SET running_until = '2000-01-01T00:00:00.000Z x'", &[]));
        let sync = || h.call("POST", &format!("/api/v1/docs-sources/{source}/sync"), None, &admin);
        let disconnected = || source_of(&h, &admin)["disconnected"].clone();
        // Sync A asks GitLab to renew the tokens; the answer is on its way when A's lease runs out.
        let refreshing = || {
            expire_token();
            let mut a = job_of(&sync());
            let Ok(Step::Fetch(calls)) = step_with(&h, &mut a, vec![]).0 else { panic!("a refresh") };
            assert_eq!(calls[0].url, "https://gitlab.com/oauth/token");
            let replies: Vec<HttpReply> = calls.iter().map(answer).collect();
            expire_lease();
            (a, replies)
        };
        // The next sync uses the newest tokens, without renewing them.
        let works = || {
            let (finish, sent) = drive(&h, job_of(&sync()), &answer);
            filled(finish);
            assert!(sent.iter().all(|c| c.url != "https://gitlab.com/oauth/token"));
            assert!(sent[0].headers.contains(&("authorization".into(), format!("Bearer glo_{}", lab.issued.borrow()))), "{:?}", sent[0]);
        };

        // Sync B takes over meanwhile: it doesn't spend the same refresh token, which GitLab would
        // refuse, while A's answer may still land.
        let (mut a, a_refresh) = refreshing();
        let (finish, sent) = drive(&h, job_of(&sync()), &answer);
        assert!(matches!(finish, Finish::Fail(ref e) if e.message.contains("Another sync is renewing")), "{finish:?}");
        assert!(sent.is_empty(), "nothing spent");
        assert_eq!(disconnected(), Value::Null);
        // A's answer lands: its tokens are kept, though A lost its lease.
        assert!(matches!(step_with(&h, &mut a, a_refresh).0, Ok(Step::Done(Finish::Fail(_)))));
        assert_eq!(disconnected(), Value::Null);
        works();

        // Past the time A's answer could take, B spends the token anyway, GitLab refuses it (A spent
        // it), and the folder waits for Reconnect. A's answer still lands: its tokens are kept and
        // the folder is back.
        let (mut a, a_refresh) = refreshing();
        db_run(&h, |db| {
            db.execute(
                "UPDATE docs_source_links SET refreshing = '2000-01-01T00:00:00.000Z' || substr(refreshing, instr(refreshing, '|'))",
                &[],
            )
        });
        let (finish, sent) = drive(&h, job_of(&sync()), &answer);
        assert!(matches!(finish, Finish::Fail(_)));
        assert_eq!(sent[0].url, "https://gitlab.com/oauth/token");
        assert!(disconnected().as_str().unwrap().contains("Reconnect"));
        assert!(matches!(step_with(&h, &mut a, a_refresh).0, Ok(Step::Done(Finish::Fail(_)))), "A lost its lease");
        assert_eq!(disconnected(), Value::Null, "A's tokens put it back");
        works();
    }
}
