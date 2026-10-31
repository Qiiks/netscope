#![cfg(target_os = "linux")]
//! Privileged integration suite for `netscoped`.
//!
//! Run as root with one test thread:
//!
//! ```text
//! sudo cargo test -p netscope-daemon --test privileged -- --ignored --test-threads=1
//! ```
//!
//! Every test starts its own daemon against a unique temp config and cgroup
//! root, and a `Drop` guard stops that daemon and removes everything the test
//! created. The veth and dummy interfaces are transient; no host route or
//! policy rule is left behind.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use netscope_linux::protocol::{
    AddProfile, ProfileStatus, Request, RequestOp, Response, StatusData,
};
use netscope_linux::types::{FilterDefault, ModeSpec, TargetSpec};
use serde_json::Value;

/// Serialise test bodies even if the operator forgets `--test-threads=1`.
static SERIAL: Mutex<()> = Mutex::new(());

struct Client {
    stream: UnixStream,
    next_id: u64,
}

impl Client {
    fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self { stream, next_id: 1 })
    }

    fn call(&mut self, op: RequestOp) -> Response {
        let id = self.next_id;
        self.next_id += 1;
        let mut line = serde_json::to_vec(&Request { id, op }).expect("serialize request");
        line.push(b'\n');
        self.stream.write_all(&line).expect("write request");
        self.stream.flush().expect("flush request");

        let mut body = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.stream.read(&mut byte) {
                Ok(0) => panic!("daemon closed the control socket"),
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    body.push(byte[0]);
                    assert!(body.len() <= 64 * 1024, "daemon response too large");
                }
                Err(err) => panic!("read daemon response: {err}"),
            }
        }
        let response: Response = serde_json::from_slice(&body).expect("parse daemon response");
        assert_eq!(response.id, id, "response id mismatch");
        response
    }

    fn status(&mut self) -> StatusData {
        let data = ok_data(self.call(RequestOp::Status));
        serde_json::from_value(data).expect("status response shape")
    }

    fn add(
        &mut self,
        name: &str,
        target: TargetSpec,
        mode: ModeSpec,
        target_uid: u32,
    ) -> ProfileStatus {
        let data = ok_data(self.call(RequestOp::Add(AddProfile {
            name: name.to_string(),
            target,
            mode,
            target_uid,
        })));
        serde_json::from_value(data).expect("add response shape")
    }

    fn list(&mut self) -> Vec<ProfileStatus> {
        let data = ok_data(self.call(RequestOp::List));
        serde_json::from_value(data).expect("list response shape")
    }

    fn refresh(&mut self) -> Value {
        ok_data(self.call(RequestOp::Refresh))
    }

    fn disable(&mut self, name: &str) -> ProfileStatus {
        let data = ok_data(self.call(RequestOp::Disable {
            name: name.to_string(),
        }));
        serde_json::from_value(data).expect("disable response shape")
    }

    fn remove(&mut self, name: &str) {
        let _ = ok_data(self.call(RequestOp::Remove {
            name: name.to_string(),
        }));
    }
}

fn ok_data(response: Response) -> Value {
    assert!(
        response.ok,
        "daemon error: {}",
        response.error.unwrap_or_default()
    );
    response.data.expect("daemon response without data")
}

struct Daemon {
    child: Option<Child>,
    config: PathBuf,
    socket: PathBuf,
    state: PathBuf,
    cgroup_root: PathBuf,
    temp: PathBuf,
    log: PathBuf,
    profile_ids: Vec<String>,
    tables: Vec<String>,
    routes: Vec<(u32, u32, u32)>,
    links: Vec<String>,
    netns: Option<String>,
    pids: Vec<(u32, Option<u64>)>,
}

impl Daemon {
    fn new(name: &str) -> Self {
        Self::new_with_poll(name, 100)
    }

    fn new_with_poll(name: &str, poll_interval_ms: u64) -> Self {
        let pid = std::process::id();
        let temp = PathBuf::from(format!("/tmp/netscope-priv-{pid}-{name}"));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).expect("create test root");
        let cgroup_root = PathBuf::from(format!("/sys/fs/cgroup/netscope-priv-{pid}-{name}"));
        assert!(
            !cgroup_root.exists(),
            "stale cgroup root {} exists; remove it before running the privileged suite",
            cgroup_root.display()
        );
        let config = temp.join("config.toml");
        let socket = temp.join("control.sock");
        let state = temp.join("state.json");
        let log = temp.join("daemon.log");
        fs::write(
            &config,
            format!(
                "[daemon]\nsocket_path = \"{}\"\nstate_path = \"{}\"\ncgroup_root = \"{}\"\npoll_interval_ms = {poll_interval_ms}\nrefresh_interval_secs = 1\nmax_profiles = 8\nlog_level = \"info\"\n",
                socket.display(),
                state.display(),
                cgroup_root.display()
            ),
        )
        .expect("write daemon config");
        let mut daemon = Self {
            child: None,
            config,
            socket,
            state,
            cgroup_root,
            temp,
            log,
            profile_ids: Vec::new(),
            tables: Vec::new(),
            routes: Vec::new(),
            links: Vec::new(),
            netns: None,
            pids: Vec::new(),
        };
        daemon.start();
        daemon
    }

    fn client(&self) -> Client {
        Client::connect(&self.socket).expect("connect to test daemon")
    }

    fn start(&mut self) {
        assert!(self.child.is_none(), "daemon already running");
        let out = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .expect("open daemon log");
        let err = out.try_clone().expect("clone daemon log");
        let child = Command::new(env!("CARGO_BIN_EXE_netscoped"))
            .arg("--config")
            .arg(&self.config)
            .arg("--foreground")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn netscoped");
        self.child = Some(child);
        self.wait_ready();
    }

    fn wait_ready(&mut self) {
        let child_pid = self.child.as_ref().expect("daemon child").id();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let exited = match self.child.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(status) => status,
                    Err(err) => panic!("daemon try_wait: {err}"),
                },
                None => panic!("daemon child missing"),
            };
            if let Some(status) = exited {
                panic!(
                    "netscoped exited during startup ({status})\n{}",
                    self.log_tail()
                );
            }
            match Client::connect(&self.socket) {
                Ok(mut client) => {
                    let status = client.status();
                    assert_eq!(status.pid, child_pid, "status pid does not match daemon");
                    assert_eq!(
                        status.cgroup_root,
                        self.cgroup_root.display().to_string(),
                        "daemon cgroup root"
                    );
                    return;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                Err(err) => panic!(
                    "control socket {} not ready: {err}\n{}",
                    self.socket.display(),
                    self.log_tail()
                ),
            }
        }
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => return,
        }
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
    }

    fn log_tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(40);
        lines[start..].join("\n")
    }

    fn track_pid(&mut self, pid: u32) {
        self.pids
            .push((pid, netscope_linux::cgroup::read_start_time(pid)));
    }

    fn track_link(&mut self, link: &str) {
        self.links.push(link.to_string());
    }

    fn track_netns(&mut self, netns: &str) {
        self.netns = Some(netns.to_string());
    }

    fn track_profile(&mut self, id: &str, status: &ProfileStatus) {
        self.profile_ids.push(id.to_string());
        self.tables.push(table_name_from_status(status));
        if status.mode == "route" {
            let mark = parse_mark(&status.mark).expect("route profile mark");
            self.routes.push((mark, status.table, status.rule_priority));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        for (pid, start) in &self.pids {
            if start.is_some() && netscope_linux::cgroup::read_start_time(*pid) == *start {
                unsafe {
                    libc::kill(*pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
        self.stop();
        for (mark, table, priority) in &self.routes {
            let mark = format!("0x{mark:x}");
            let table = table.to_string();
            let priority = priority.to_string();
            let _ = Command::new("ip")
                .args([
                    "-4",
                    "rule",
                    "del",
                    "fwmark",
                    mark.as_str(),
                    "table",
                    table.as_str(),
                    "pref",
                    priority.as_str(),
                ])
                .status();
            let _ = Command::new("ip")
                .args(["-4", "route", "flush", "table", table.as_str()])
                .status();
        }
        for table in &self.tables {
            let _ = Command::new("nft")
                .args(["delete", "table", "inet", table.as_str()])
                .status();
        }
        for link in &self.links {
            let _ = Command::new("ip")
                .args(["link", "del", link.as_str()])
                .status();
        }
        if let Some(netns) = &self.netns {
            let _ = Command::new("ip")
                .args(["netns", "del", netns.as_str()])
                .status();
        }
        for id in &self.profile_ids {
            let _ = fs::remove_dir(self.cgroup_root.join(id));
        }
        let _ = fs::remove_dir(&self.cgroup_root);
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.state);
        let _ = fs::remove_dir_all(&self.temp);
    }
}

fn filter_drop() -> ModeSpec {
    ModeSpec::Filter {
        default: FilterDefault::Drop,
        allow_cidrs: Vec::new(),
        deny_cidrs: Vec::new(),
    }
}

fn parse_mark(text: &str) -> Option<u32> {
    text.strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| text.parse().ok())
}

fn table_name_from_status(status: &ProfileStatus) -> String {
    status
        .nft_table
        .strip_prefix("inet ")
        .unwrap_or(status.nft_table.as_str())
        .to_string()
}

fn run_cmd(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("spawn {program}: {err}"));
    assert!(
        output.status.success(),
        "{program} {} failed ({}): {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn run_ip(args: &[&str]) {
    let _ = run_cmd("ip", args);
}

fn ip_json(args: &[&str]) -> Value {
    let text = run_cmd("ip", args);
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn nft_tables() -> Vec<String> {
    let text = run_cmd("nft", &["-j", "list", "tables"]);
    let value: Value = serde_json::from_str(&text).expect("nft tables json");
    value
        .get("nftables")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    let table = entry.get("table")?;
                    let name = table.get("name")?;
                    name.as_str().map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn value_u32(value: &Value) -> Option<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).ok();
    }
    let text = value.as_str()?;
    text.strip_prefix("0x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| text.parse().ok())
}

fn has_rule(family: &str, mark: u32, table: u32) -> bool {
    let value = ip_json(&[family, "-j", "rule", "show"]);
    value.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            let entry_mark = entry
                .get("fwmark")
                .and_then(value_u32)
                .or_else(|| entry.get("mark").and_then(value_u32));
            entry_mark == Some(mark) && entry.get("table").and_then(value_u32) == Some(table)
        })
    })
}

fn table_has_blackhole(table: u32) -> bool {
    let table = table.to_string();
    let value = ip_json(&["-4", "-j", "route", "show", "table", &table]);
    value.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("blackhole")
                && entry.get("dst").and_then(Value::as_str) == Some("default")
        })
    })
}

fn route_get(mark: u32) -> Value {
    let mark = format!("0x{mark:x}");
    let value = ip_json(&["-4", "-j", "route", "get", "1.1.1.1", "mark", &mark]);
    value
        .as_array()
        .and_then(|entries| entries.first())
        .cloned()
        .unwrap_or(Value::Null)
}

fn cgroup_procs(root: &Path, id: &str) -> Vec<u32> {
    fs::read_to_string(root.join(id).join("cgroup.procs"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

fn wait_for_cgroup(daemon: &Daemon, id: &str, pid: u32, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if cgroup_procs(&daemon.cgroup_root, id).contains(&pid) {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "pid {pid} was not attached to {} within {timeout:?}\n{}",
                daemon.cgroup_root.join(id).display(),
                daemon.log_tail()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn route_table_is_empty(table: &str) -> bool {
    let output = Command::new("ip")
        .args(["-4", "-j", "route", "show", "table", table])
        .output()
        .unwrap_or_else(|err| panic!("spawn ip: {err}"));
    if output.status.success() {
        let routes: Value = serde_json::from_slice(&output.stdout).expect("ip route show json");
        return routes.as_array().is_none_or(|entries| entries.is_empty());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist"),
        "ip -4 route show table {table} failed ({}): {}",
        output.status,
        stderr.trim()
    );
    true
}

fn preflight() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged suite requires root with CAP_NET_ADMIN and CAP_SYS_ADMIN"
    );
    assert!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "cgroup v2 is required at /sys/fs/cgroup"
    );
    let _ = run_cmd("nft", &["--version"]);
    let _ = run_cmd("ip", &["-V"]);

    let leftovers: Vec<String> = nft_tables()
        .into_iter()
        .filter(|table| table.starts_with("netscope_"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "host already has netscope nft tables {leftovers:?}; stop netscoped and remove its profiles first"
    );

    for family in ["-4", "-6"] {
        let rules = ip_json(&[family, "-j", "rule", "show"]);
        if let Some(entries) = rules.as_array() {
            for entry in entries {
                if let Some(table) = entry.get("table").and_then(value_u32) {
                    assert!(
                        !(20000..=20031).contains(&table),
                        "host already has a policy rule in table {table}; stop netscoped and remove its profiles first"
                    );
                }
            }
        }
    }
    for table in 20000..=20031u32 {
        let table = table.to_string();
        assert!(
            route_table_is_empty(&table),
            "host route table {table} is not empty; stop netscoped and remove its profiles first"
        );
    }
}

fn build_fixture(dir: &Path) -> (PathBuf, PathBuf) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/udp_fixture.rs");
    let sender = dir.join("udp-send");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(&rustc)
        .arg("--edition=2021")
        .arg("-o")
        .arg(&sender)
        .arg(&source)
        .output()
        .unwrap_or_else(|err| panic!("spawn rustc: {err}"));
    assert!(
        output.status.success(),
        "rustc fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::set_permissions(&sender, fs::Permissions::from_mode(0o755)).expect("chmod sender fixture");
    let receiver = dir.join("udp-recv");
    fs::copy(&sender, &receiver).expect("copy receiver fixture");
    fs::set_permissions(&receiver, fs::Permissions::from_mode(0o755))
        .expect("chmod receiver fixture");
    (sender, receiver)
}

fn setup_veth(ns: &str, daemon: &mut Daemon) -> String {
    let pid = std::process::id();
    let host = format!("nsv0{}", pid % 10000);
    let peer = format!("nsv1{}", pid % 10000);
    let octet = pid % 250;
    let host_cidr = format!("10.201.{octet}.1/24");
    let peer_cidr = format!("10.201.{octet}.2/24");
    let peer_ip = format!("10.201.{octet}.2");

    run_ip(&["netns", "add", ns]);
    daemon.track_netns(ns);
    run_ip(&[
        "link",
        "add",
        host.as_str(),
        "type",
        "veth",
        "peer",
        "name",
        peer.as_str(),
    ]);
    daemon.track_link(&host);
    run_ip(&["link", "set", peer.as_str(), "netns", ns]);
    run_ip(&["addr", "add", host_cidr.as_str(), "dev", host.as_str()]);
    run_ip(&["link", "set", host.as_str(), "up"]);
    run_ip(&[
        "netns",
        "exec",
        ns,
        "ip",
        "addr",
        "add",
        peer_cidr.as_str(),
        "dev",
        peer.as_str(),
    ]);
    run_ip(&[
        "netns",
        "exec",
        ns,
        "ip",
        "link",
        "set",
        peer.as_str(),
        "up",
    ]);
    run_ip(&["netns", "exec", ns, "ip", "link", "set", "lo", "up"]);
    peer_ip
}

fn spawn_receiver(ns: &str, bin: &Path, port: u16) -> Child {
    let port = port.to_string();
    Command::new("ip")
        .args(["netns", "exec", ns])
        .arg(bin)
        .args(["recv", &port])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn udp receiver")
}

fn run_sender(
    daemon: &mut Daemon,
    bin: &Path,
    dst: &str,
    steam_env: bool,
    wait_id: Option<&str>,
    timeout: Duration,
) {
    let mut command = Command::new(bin);
    command
        .args(["send", dst])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if steam_env {
        command
            .env("SteamAppId", "12345")
            .env("SteamGameId", "12345");
    }
    let mut child = command.spawn().expect("spawn udp sender");
    let pid = child.id();
    daemon.track_pid(pid);
    if let Some(id) = wait_id {
        wait_for_cgroup(daemon, id, pid, timeout);
    }
    child
        .stdin
        .take()
        .expect("sender stdin")
        .write_all(b"x")
        .expect("gate sender");
    let output = child.wait_with_output().expect("wait for udp sender");
    assert!(
        output.status.success(),
        "udp sender failed ({}): {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        daemon.log_tail()
    );
    thread::sleep(Duration::from_millis(200));
}

fn receiver_count(receiver: Child, daemon: &Daemon) -> u32 {
    let output = receiver.wait_with_output().expect("wait for udp receiver");
    assert!(
        output.status.success(),
        "udp receiver failed ({}): {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        daemon.log_tail()
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let count = text
        .trim()
        .strip_prefix("received=")
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("unexpected receiver output {text:?}"));
    count
}

#[test]
#[ignore = "requires root and CAP_NET_ADMIN"]
fn fanotify_pre_exec_attach() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflight();
    let mut daemon = Daemon::new("fan");
    let mut client = daemon.client();
    let pid = std::process::id();

    let copy = daemon.temp.join("sleep-copy");
    fs::copy("/bin/sleep", &copy).expect("copy /bin/sleep");
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).expect("chmod sleep copy");

    let id = format!("fan-{pid}");
    let added = client.add(
        &id,
        TargetSpec::Native {
            path: copy.display().to_string(),
        },
        filter_drop(),
        0,
    );
    daemon.track_profile(&id, &added);
    assert!(
        !added
            .warnings
            .iter()
            .any(|warning| warning.contains("fanotify unavailable")),
        "fanotify unavailable, cannot prove pre-exec attach: {:?}",
        added.warnings
    );

    let started = Instant::now();
    let mut child = Command::new(&copy)
        .arg("5")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep copy");
    let child_pid = child.id();
    daemon.track_pid(child_pid);

    let deadline = started + Duration::from_millis(500);
    loop {
        let profiles = client.list();
        let profile = profiles
            .iter()
            .find(|profile| profile.id == id)
            .expect("fanotify profile in list");
        if profile.pids.contains(&child_pid) {
            assert!(
                cgroup_procs(&daemon.cgroup_root, &id).contains(&child_pid),
                "pid {child_pid} missing from {}/cgroup.procs",
                daemon.cgroup_root.join(&id).display()
            );
            assert_eq!(
                profile.attached, "pre-exec",
                "expected pre-exec attach, got {} (warnings: {:?})",
                profile.attached, profile.warnings
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "pid {child_pid} not attached within 500 ms: {profile:?}\n{}",
            daemon.log_tail()
        );
        thread::sleep(Duration::from_millis(10));
    }

    client.remove(&id);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[ignore = "requires root and CAP_NET_ADMIN"]
fn wine_pre_open_attach() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflight();
    // The poll loop must not win the race this test is about.
    let mut daemon = Daemon::new_with_poll("wine", 10_000);
    let mut client = daemon.client();
    let pid = std::process::id();
    let (fixture, _) = build_fixture(&daemon.temp);

    let pe = daemon.temp.join("game.exe");
    fs::write(&pe, b"MZ\x90\x00fake pe").expect("write fake PE");
    let pe_canonical = fs::canonicalize(&pe).expect("canonical PE");

    let id = format!("wine-{pid}");
    let added = client.add(
        &id,
        TargetSpec::Wine {
            path: pe.display().to_string(),
        },
        filter_drop(),
        0,
    );
    daemon.track_profile(&id, &added);
    assert!(
        !added
            .warnings
            .iter()
            .any(|warning| warning.contains("fanotify unavailable")),
        "fanotify unavailable, cannot prove pre-open attach: {:?}",
        added.warnings
    );

    // A loader-shaped copy exercises the Wine-process guard without Wine.
    let loader = daemon.temp.join("wine64-preloader");
    fs::copy(&fixture, &loader).expect("copy wine loader");
    fs::set_permissions(&loader, fs::Permissions::from_mode(0o755)).expect("chmod wine loader");

    let mut child = Command::new(&loader)
        .arg("open-sleep")
        .arg(&pe)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn wine loader");
    let child_pid = child.id();
    daemon.track_pid(child_pid);

    let mut opened = String::new();
    BufReader::new(child.stdout.take().expect("loader stdout"))
        .read_line(&mut opened)
        .expect("read loader output");
    assert_eq!(
        opened.trim(),
        "opened",
        "wine loader did not finish its open\n{}",
        daemon.log_tail()
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let profiles = client.list();
        let profile = profiles
            .iter()
            .find(|profile| profile.id == id)
            .expect("wine profile in list");
        if profile.pids.contains(&child_pid) {
            assert_eq!(
                profile.attached, "pre-open",
                "expected pre-open attach, got {} (warnings: {:?})",
                profile.attached, profile.warnings
            );
            assert_eq!(
                profile.target,
                format!("wine:{}", pe_canonical.display()),
                "wine profile target label"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "pid {child_pid} not attached within 1 s: {profile:?}\n{}",
            daemon.log_tail()
        );
        thread::sleep(Duration::from_millis(10));
    }

    // The same PE opened by a non-Wine process must be allowed and unscoped.
    let other = daemon.temp.join("not-wine");
    fs::copy(&fixture, &other).expect("copy non-wine opener");
    fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).expect("chmod non-wine opener");
    let mut other_child = Command::new(&other)
        .arg("open-sleep")
        .arg(&pe)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn non-wine opener");
    let other_pid = other_child.id();
    daemon.track_pid(other_pid);
    thread::sleep(Duration::from_millis(500));
    assert!(
        !cgroup_procs(&daemon.cgroup_root, &id).contains(&other_pid),
        "non-Wine opener {other_pid} was scoped\n{}",
        daemon.log_tail()
    );
    assert!(
        other_child
            .try_wait()
            .expect("non-wine opener status")
            .is_none(),
        "non-Wine opener was not allowed through its open\n{}",
        daemon.log_tail()
    );

    client.remove(&id);
    let _ = other_child.kill();
    let _ = other_child.wait();
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[ignore = "requires root and CAP_NET_ADMIN"]
fn filter_drop_with_veth_peer() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflight();
    let mut daemon = Daemon::new("filter");
    let mut client = daemon.client();
    let pid = std::process::id();
    let (send_bin, recv_bin) = build_fixture(&daemon.temp);
    let ns = format!("nspriv{pid}");
    let peer_ip = setup_veth(&ns, &mut daemon);
    let port = 40000 + (pid % 20000) as u16;
    let receiver = spawn_receiver(&ns, &recv_bin, port);
    daemon.track_pid(receiver.id());
    thread::sleep(Duration::from_millis(300));

    let id = format!("filter-{pid}");
    let added = client.add(
        &id,
        TargetSpec::Native {
            path: send_bin.display().to_string(),
        },
        filter_drop(),
        0,
    );
    daemon.track_profile(&id, &added);
    let dst = format!("{peer_ip}:{port}");

    run_sender(
        &mut daemon,
        &send_bin,
        &dst,
        false,
        Some(&id),
        Duration::from_secs(2),
    );
    client.disable(&id);
    run_sender(&mut daemon, &send_bin, &dst, false, None, Duration::ZERO);

    let count = receiver_count(receiver, &daemon);
    assert_eq!(
        count,
        1,
        "expected the scoped packet dropped and the unscoped packet delivered\n{}",
        daemon.log_tail()
    );
    client.remove(&id);
}

#[test]
#[ignore = "requires root and CAP_NET_ADMIN"]
fn route_mark_table_blackhole() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflight();
    let mut daemon = Daemon::new("route");
    let mut client = daemon.client();
    let pid = std::process::id();

    let dummy = format!("nsd{}", pid % 100000);
    run_ip(&["link", "add", dummy.as_str(), "type", "dummy"]);
    daemon.track_link(&dummy);
    run_ip(&["link", "set", dummy.as_str(), "up"]);

    let id = format!("route-{pid}");
    let added = client.add(
        &id,
        TargetSpec::Native {
            path: "/bin/true".to_string(),
        },
        ModeSpec::Route {
            interface: dummy.clone(),
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        },
        0,
    );
    daemon.track_profile(&id, &added);
    let mark = parse_mark(&added.mark).expect("route mark");
    assert_eq!(mark, 0x4e53, "first profile fwmark");
    assert_eq!(added.table, 20000, "first profile table");
    assert_eq!(added.rule_priority, 1000, "first profile priority");
    assert!(has_rule("-4", mark, added.table), "fwmark rule missing");
    assert!(
        table_has_blackhole(added.table),
        "blackhole default missing from table {}",
        added.table
    );

    let route = route_get(mark);
    assert_eq!(
        route.get("dev").and_then(Value::as_str),
        Some(dummy.as_str()),
        "route get did not select the dummy: {route}"
    );

    let table_arg = added.table.to_string();
    run_ip(&[
        "-4",
        "route",
        "del",
        "default",
        "dev",
        dummy.as_str(),
        "table",
        table_arg.as_str(),
        "metric",
        "100",
    ]);
    let routes = ip_json(&["-4", "-j", "route", "show", "table", table_arg.as_str()]);
    assert!(
        table_has_blackhole(added.table),
        "blackhole default disappeared from table {}",
        added.table
    );
    assert!(
        !routes.as_array().is_some_and(|entries| entries
            .iter()
            .any(|entry| entry.get("type").and_then(Value::as_str) != Some("blackhole"))),
        "table {} is not fail-closed after removing the dev default: {routes}",
        added.table
    );

    client.remove(&id);
    assert!(!has_rule("-4", mark, added.table), "rule survived remove");
    let table = table_name_from_status(&added);
    assert!(
        !nft_tables().contains(&table),
        "nft table {table} survived remove"
    );
}

#[test]
#[ignore = "requires root and CAP_NET_ADMIN"]
fn steam_env_attach_and_drop() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflight();
    let mut daemon = Daemon::new("steam");
    let mut client = daemon.client();
    let pid = std::process::id();
    let (send_bin, recv_bin) = build_fixture(&daemon.temp);
    let ns = format!("nspriv{pid}");
    let peer_ip = setup_veth(&ns, &mut daemon);
    let port = 40000 + (pid % 20000) as u16;
    let receiver = spawn_receiver(&ns, &recv_bin, port);
    daemon.track_pid(receiver.id());
    thread::sleep(Duration::from_millis(300));

    let id = format!("steam-{pid}");
    let added = client.add(&id, TargetSpec::Steam { app_id: 12345 }, filter_drop(), 0);
    daemon.track_profile(&id, &added);
    let dst = format!("{peer_ip}:{port}");

    let mut sender = Command::new(&send_bin)
        .args(["send", dst.as_str()])
        .env("SteamAppId", "12345")
        .env("SteamGameId", "12345")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn steam sender");
    let sender_pid = sender.id();
    daemon.track_pid(sender_pid);
    wait_for_cgroup(&daemon, &id, sender_pid, Duration::from_secs(1));
    let status = client.status();
    let profile = status
        .profiles
        .iter()
        .find(|profile| profile.id == id)
        .expect("steam profile in status");
    assert!(
        profile.pids.contains(&sender_pid),
        "steam pid not listed in profile: {profile:?}"
    );
    assert_eq!(
        profile.attached, "late",
        "steam attach should be poll (late), got {}",
        profile.attached
    );

    sender
        .stdin
        .take()
        .expect("steam sender stdin")
        .write_all(b"x")
        .expect("gate steam sender");
    let output = sender.wait_with_output().expect("wait for steam sender");
    assert!(
        output.status.success(),
        "steam sender failed ({}): {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        daemon.log_tail()
    );
    thread::sleep(Duration::from_millis(200));

    run_sender(&mut daemon, &send_bin, &dst, false, None, Duration::ZERO);

    let count = receiver_count(receiver, &daemon);
    assert_eq!(
        count,
        1,
        "expected the steam packet dropped and the unscoped packet delivered\n{}",
        daemon.log_tail()
    );
    client.remove(&id);
}

#[test]
#[ignore = "requires root and CAP_NET_ADMIN"]
fn restart_reconcile_and_cleanup() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    preflight();
    let mut daemon = Daemon::new("restart");
    let pid = std::process::id();

    let dummy = format!("nsd{}", pid % 100000);
    run_ip(&["link", "add", dummy.as_str(), "type", "dummy"]);
    daemon.track_link(&dummy);
    run_ip(&["link", "set", dummy.as_str(), "up"]);

    let route_id = format!("keep-route-{pid}");
    let filter_id = format!("keep-filter-{pid}");
    let mut client = daemon.client();
    let route = client.add(
        &route_id,
        TargetSpec::Native {
            path: "/bin/true".to_string(),
        },
        ModeSpec::Route {
            interface: dummy.clone(),
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        },
        0,
    );
    daemon.track_profile(&route_id, &route);
    let filter = client.add(
        &filter_id,
        TargetSpec::Native {
            path: "/bin/cat".to_string(),
        },
        filter_drop(),
        0,
    );
    daemon.track_profile(&filter_id, &filter);

    let route_table = table_name_from_status(&route);
    let filter_table = table_name_from_status(&filter);
    let mark = parse_mark(&route.mark).expect("route mark");
    assert!(
        nft_tables().contains(&route_table),
        "route table missing after add"
    );
    assert!(
        nft_tables().contains(&filter_table),
        "filter table missing after add"
    );
    assert!(
        has_rule("-4", mark, route.table),
        "route rule missing after add"
    );
    assert!(daemon.cgroup_root.join(&route_id).is_dir());
    assert!(daemon.cgroup_root.join(&filter_id).is_dir());

    client.remove(&filter_id);
    assert!(
        !nft_tables().contains(&filter_table),
        "filter table survived remove"
    );
    assert!(
        !daemon.cgroup_root.join(&filter_id).exists(),
        "filter cgroup survived remove"
    );

    drop(client);
    daemon.stop();
    assert!(
        !nft_tables().contains(&route_table),
        "route table survived graceful stop"
    );
    assert!(
        !has_rule("-4", mark, route.table),
        "route rule survived graceful stop"
    );

    daemon.start();
    let mut client = daemon.client();
    let refreshed = client.refresh();
    assert!(
        refreshed.get("updated").and_then(Value::as_u64).is_some(),
        "refresh response: {refreshed}"
    );
    let profiles = client.list();
    assert!(
        profiles
            .iter()
            .any(|profile| profile.id == route_id && profile.enabled),
        "route profile not restored: {profiles:?}"
    );
    assert!(
        profiles.iter().all(|profile| profile.id != filter_id),
        "removed filter profile was restored: {profiles:?}"
    );
    assert!(
        nft_tables().contains(&route_table),
        "route table not reapplied after restart\n{}",
        daemon.log_tail()
    );
    assert!(
        has_rule("-4", mark, route.table),
        "route rule not reapplied after restart\n{}",
        daemon.log_tail()
    );
    assert!(
        daemon.cgroup_root.join(&route_id).is_dir(),
        "route cgroup not recreated\n{}",
        daemon.log_tail()
    );
    assert!(
        !nft_tables().contains(&filter_table),
        "removed filter table reappeared after restart\n{}",
        daemon.log_tail()
    );
    assert!(
        !daemon.cgroup_root.join(&filter_id).exists(),
        "removed filter cgroup reappeared after restart\n{}",
        daemon.log_tail()
    );

    client.remove(&route_id);
    assert!(
        !nft_tables().contains(&route_table),
        "route table survived remove\n{}",
        daemon.log_tail()
    );
    assert!(
        !has_rule("-4", mark, route.table),
        "rule survived remove\n{}",
        daemon.log_tail()
    );
    assert!(
        !daemon.cgroup_root.join(&route_id).exists(),
        "route cgroup survived remove\n{}",
        daemon.log_tail()
    );

    drop(client);
    daemon.stop();
    daemon.start();
    let _client = daemon.client();
    let tables = nft_tables();
    assert!(
        tables.iter().all(|table| !table.starts_with("netscope_")),
        "netscope tables remain after restart: {tables:?}\n{}",
        daemon.log_tail()
    );
    for family in ["-4", "-6"] {
        let rules = ip_json(&[family, "-j", "rule", "show"]);
        if let Some(entries) = rules.as_array() {
            for entry in entries {
                if let Some(table) = entry.get("table").and_then(value_u32) {
                    assert!(
                        !(20000..=20031).contains(&table),
                        "policy rule in table {table} remains after restart\n{}",
                        daemon.log_tail()
                    );
                }
            }
        }
    }
    let dirs: Vec<String> = fs::read_dir(&daemon.cgroup_root)
        .expect("read cgroup root")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            entry
                .file_type()
                .ok()?
                .is_dir()
                .then_some(entry.file_name().to_string_lossy().into_owned())
        })
        .collect();
    assert!(
        dirs.is_empty(),
        "cgroup directories remain after restart: {dirs:?}\n{}",
        daemon.log_tail()
    );
}
