//! End-to-end tests against a mock `netscoped` control socket.
//!
//! Each test starts a real Unix domain socket server in a background thread,
//! drives it through [`Client`], and asserts both the typed reply the client
//! returns and the newline-delimited JSON the server actually received.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use netscope_client::{
    Client, ClientError, CloseResult, FilterDefault, Hold, OpenScope, PolicySpec, ProfileStatus,
    ScopeHandle, StatusData, TargetSpec,
};
use serde_json::{json, Value};

/// What the mock daemon sends back for one request.
type Reply = Result<Value, String>;

/// A one-request-at-a-time `netscoped` stand-in speaking NDJSON over a Unix
/// socket. It records every request it decodes and counts client disconnects.
struct MockDaemon {
    path: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
    disconnects: Arc<(Mutex<usize>, Condvar)>,
}

impl MockDaemon {
    fn start(handler: impl Fn(&Value) -> Reply + Send + 'static) -> Self {
        let path = socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock control socket");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let disconnects = Arc::new((Mutex::new(0), Condvar::new()));

        let requests_for_server = Arc::clone(&requests);
        let disconnects_for_server = Arc::clone(&disconnects);
        // Dropping the handle detaches the accept loop; tests never join it.
        let _accept = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                serve(
                    stream,
                    &handler,
                    &requests_for_server,
                    &disconnects_for_server,
                );
            }
        });

        Self {
            path,
            requests,
            disconnects,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("request log").clone()
    }

    fn wait_for_disconnect(&self, timeout: Duration) {
        let (count, wake) = &*self.disconnects;
        let count = count.lock().expect("disconnect count");
        let count = wake
            .wait_timeout_while(count, timeout, |count| *count == 0)
            .expect("wait for client disconnect")
            .0;
        assert!(
            *count > 0,
            "mock daemon did not observe the client disconnect"
        );
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Reads requests until the client hangs up, replying to each one.
fn serve(
    stream: std::os::unix::net::UnixStream,
    handler: &impl Fn(&Value) -> Reply,
    requests: &Mutex<Vec<Value>>,
    disconnects: &(Mutex<usize>, Condvar),
) {
    let mut writer = stream.try_clone().expect("clone mock stream");
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let request: Value = serde_json::from_str(line.trim_end()).expect("request is JSON");
        let id = request
            .get("id")
            .and_then(Value::as_u64)
            .expect("request id");
        requests.lock().expect("request log").push(request.clone());

        let reply = match handler(&request) {
            Ok(data) => json!({"id": id, "ok": true, "data": data, "error": null}),
            Err(error) => json!({"id": id, "ok": false, "data": null, "error": error}),
        };
        let mut encoded = serde_json::to_vec(&reply).expect("encode response");
        encoded.push(b'\n');
        if writer.write_all(&encoded).is_err() {
            break;
        }
    }

    let (count, wake) = disconnects;
    *count.lock().expect("disconnect count") += 1;
    wake.notify_all();
}

fn socket_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "netscope-client-it-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn status_fixture() -> StatusData {
    StatusData {
        api_version: 2,
        daemon_version: "0.2.1-integration".to_string(),
        pid: 4242,
        kernel: "test".to_string(),
        cgroup_root: "/sys/fs/cgroup/netscope".to_string(),
        state_path: "/var/lib/netscope/state.json".to_string(),
        config_path: "/etc/netscope/config.toml".to_string(),
        profiles: Vec::new(),
    }
}

fn profile_fixture() -> ProfileStatus {
    ProfileStatus {
        id: "overwatch".to_string(),
        mode: "filter".to_string(),
        enabled: true,
        target: "name:Overwatch.exe".to_string(),
        cgroup: "/sys/fs/cgroup/netscope/overwatch".to_string(),
        cgroup_level: 4,
        pids: vec![123],
        nft_table: "netscope_overwatch".to_string(),
        mark: "0x4e53".to_string(),
        table: 20_000,
        rule_priority: 1_000,
        attached: "exec".to_string(),
        healthy: true,
        warnings: Vec::new(),
        consumers: vec!["exitlink".to_string()],
        policies: vec!["filter".to_string()],
        generation: 7,
        links: Vec::new(),
    }
}

fn scope_fixture() -> ScopeHandle {
    ScopeHandle {
        profile: "overwatch".to_string(),
        generation: 7,
        target: "name:Overwatch.exe".to_string(),
        target_uid: 1000,
        state: "attached".to_string(),
        attached: "exec".to_string(),
        pids: vec![123],
        consumers: vec!["exitlink".to_string()],
    }
}

#[test]
fn test_status_roundtrip() {
    let expected = status_fixture();
    let sent = expected.clone();
    let daemon =
        MockDaemon::start(move |_| Ok(serde_json::to_value(&sent).expect("encode status")));

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    let status = client.status().expect("status");

    assert_eq!(status.daemon_version, "0.2.1-integration");
    assert_eq!(status.api_version, 2);
    assert_eq!(status, expected);
    assert_eq!(daemon.requests(), vec![json!({"id": 1, "op": "status"})]);
}

#[test]
fn test_open_and_close_scope() {
    let scope = scope_fixture();
    let closed = CloseResult {
        profile: "overwatch".to_string(),
        released: true,
        removed: true,
        consumers: Vec::new(),
    };
    let scope_reply = serde_json::to_value(&scope).expect("encode scope");
    let close_reply = serde_json::to_value(&closed).expect("encode close result");
    let daemon = MockDaemon::start(move |request| match request["op"].as_str() {
        Some("open") => Ok(scope_reply.clone()),
        Some("close") => Ok(close_reply.clone()),
        other => Err(format!("unexpected op: {other:?}")),
    });

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    let opened = client
        .open_process("exitlink", "Overwatch.exe", 1000, Hold::Persistent)
        .expect("open scope");
    assert_eq!(opened, scope);

    let result = client
        .close_scope(&opened.profile, "exitlink")
        .expect("close scope");
    assert_eq!(result, closed);

    let requests = daemon.requests();
    assert_eq!(requests.len(), 2, "open then close");
    assert_eq!(
        requests[0],
        json!({
            "id": 1,
            "op": "open",
            "consumer": "exitlink",
            "target": {"kind": "name", "name": "Overwatch.exe"},
            "target_uid": 1000,
            "name": null,
            "hold": "persistent",
        })
    );
    assert_eq!(
        requests[1],
        json!({"id": 2, "op": "close", "profile": "overwatch", "consumer": "exitlink"})
    );
}

#[test]
fn test_set_policy_and_clear() {
    let daemon = MockDaemon::start(|request| match request["op"].as_str() {
        Some("set_policy" | "clear_policy") => Ok(Value::Null),
        other => Err(format!("unexpected op: {other:?}")),
    });

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    client
        .set_policy(
            "overwatch",
            "exitlink",
            PolicySpec::Filter {
                default: FilterDefault::Drop,
                allow_cidrs: vec!["10.0.0.0/8".to_string()],
                deny_cidrs: Vec::new(),
            },
        )
        .expect("set policy");
    client
        .clear_policy("overwatch", "exitlink")
        .expect("clear policy");

    let requests = daemon.requests();
    assert_eq!(requests.len(), 2, "set then clear");
    assert_eq!(
        requests[0],
        json!({
            "id": 1,
            "op": "set_policy",
            "profile": "overwatch",
            "consumer": "exitlink",
            "policy": {
                "kind": "filter",
                "default": "drop",
                "allow_cidrs": ["10.0.0.0/8"],
                "deny_cidrs": [],
            },
        })
    );
    assert_eq!(
        requests[1],
        json!({"id": 2, "op": "clear_policy", "profile": "overwatch", "consumer": "exitlink"})
    );
}

#[test]
fn test_resolve() {
    let profile = profile_fixture();
    let reply = serde_json::to_value(&profile).expect("encode profile");
    let daemon = MockDaemon::start(move |request| {
        if request["op"] != "resolve" {
            return Err(format!("unexpected op: {:?}", request["op"]));
        }
        if request["profile"] == "overwatch" {
            Ok(reply.clone())
        } else {
            Ok(Value::Null)
        }
    });

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    let found = client
        .resolve(Some("overwatch"), None, None)
        .expect("resolve known profile");
    assert_eq!(found, Some(profile));

    let missing = client
        .resolve(Some("missing"), None, None)
        .expect("resolve unknown profile");
    assert_eq!(missing, None);

    let requests = daemon.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0],
        json!({
            "id": 1,
            "op": "resolve",
            "profile": "overwatch",
            "target": null,
            "target_uid": null,
        })
    );
}

#[test]
fn test_list() {
    let profiles = vec![profile_fixture()];
    let reply = serde_json::to_value(&profiles).expect("encode profile list");
    let daemon = MockDaemon::start(move |request| {
        if request["op"] != "list" {
            return Err(format!("unexpected op: {:?}", request["op"]));
        }
        Ok(reply.clone())
    });

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    let listed = client.list().expect("list");
    assert_eq!(listed, profiles);
    assert_eq!(daemon.requests(), vec![json!({"id": 1, "op": "list"})]);
}

#[test]
fn test_daemon_error_mapping() {
    let daemon = MockDaemon::start(|_| Err("target not allowed".to_string()));

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    let error = client
        .open_process("exitlink", "Overwatch.exe", 1000, Hold::Persistent)
        .expect_err("open must fail");

    assert!(
        matches!(&error, ClientError::Daemon(message) if message == "target not allowed"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn test_peer_hold_disconnect() {
    let reply = serde_json::to_value(scope_fixture()).expect("encode scope");
    let daemon = MockDaemon::start(move |request| {
        if request["op"] != "open" {
            return Err(format!("unexpected op: {:?}", request["op"]));
        }
        Ok(reply.clone())
    });

    let mut client = Client::connect_at(daemon.path()).expect("connect mock daemon");
    let scope = client
        .open_scope(OpenScope {
            consumer: "exitlink".to_string(),
            target: TargetSpec::Name {
                name: "Overwatch.exe".to_string(),
            },
            target_uid: 1000,
            name: None,
            hold: Hold::Peer,
        })
        .expect("open peer-held scope");
    assert_eq!(scope, scope_fixture());

    let requests = daemon.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["hold"], "peer");

    // A peer claim lives exactly as long as its connection.
    drop(client);
    daemon.wait_for_disconnect(Duration::from_secs(5));
}
