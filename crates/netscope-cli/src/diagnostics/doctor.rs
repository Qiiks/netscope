use std::ffi::CString;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

use netscope_linux::cgroup::CgroupManager;
use netscope_linux::ip;
use netscope_linux::nft::NftManager;
use netscope_linux::protocol::{RequestOp, API_VERSION};
use netscope_linux::types::{
    mark, profile_id_valid, rule_priority, table, Config, Mode, State, Target,
};
use serde_json::{json, Value};

use crate::client;

use super::run_capped;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    fn table(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }

    fn json(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(name: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

pub fn doctor(args: &netscope_linux::types::DoctorArgs) -> i32 {
    let socket = client::socket_path(args.socket.as_deref());
    let checks = run_checks(&socket);
    let ok = checks.iter().all(|check| check.status != Status::Fail);
    if args.json {
        println!("{}", render_json(&checks, ok));
    } else {
        print!("{}", render_text(&checks));
    }
    if ok {
        0
    } else {
        1
    }
}

pub(crate) fn run_checks(socket: &Path) -> Vec<Check> {
    let (config, config_problems) = load_config();
    let state = load_state(&config.daemon.state_path);
    let mut checks = vec![
        check_root(),
        check_kernel(),
        check_cgroup2(),
        check_tools(),
        check_daemon(socket),
    ];
    checks.push(check_state(
        &config,
        config_problems,
        state.as_ref().map(Option::as_ref).map_err(String::as_str),
    ));
    checks.push(check_profile_runtime(
        &config,
        state.as_ref().ok().and_then(Option::as_ref),
    ));
    checks
}

pub(crate) fn render_text(checks: &[Check]) -> String {
    let mut out = format!("{:<24} {:<6} {}\n", "CHECK", "STATUS", "DETAIL");
    for check in checks {
        out.push_str(&format!(
            "{:<24} {:<6} {}\n",
            check.name,
            check.status.table(),
            check.detail
        ));
    }
    out
}

pub(crate) fn render_json(checks: &[Check], ok: bool) -> String {
    let checks: Vec<Value> = checks
        .iter()
        .map(|check| {
            json!({
                "check": check.name,
                "status": check.status.json(),
                "detail": check.detail,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({ "ok": ok, "checks": checks }))
        .unwrap_or_else(|_| "{\"ok\":false,\"checks\":[]}".to_string())
}

fn check_root() -> Check {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        check("root", Status::Pass, "euid 0")
    } else {
        check(
            "root",
            Status::Fail,
            format!("euid {euid}; rerun with sudo for the complete report"),
        )
    }
}

pub(crate) fn kernel_release() -> Option<String> {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return None;
    }
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) };
    Some(release.to_string_lossy().into_owned())
}

fn check_kernel() -> Check {
    let Some(release) = kernel_release() else {
        return check("kernel", Status::Fail, "uname failed");
    };
    match parse_kernel(&release) {
        Some(version) if version >= (5, 13) => {
            check("kernel", Status::Pass, format!("{release} (>= 5.13)"))
        }
        Some(_) => check(
            "kernel",
            Status::Fail,
            format!("{release} is older than 5.13"),
        ),
        None => check(
            "kernel",
            Status::Fail,
            format!("cannot parse kernel release '{release}'"),
        ),
    }
}

fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let head: String = release
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect();
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn check_cgroup2() -> Check {
    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    let path = CString::new("/sys/fs/cgroup").expect("static path");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statfs(path.as_ptr(), &mut stat) };
    if rc != 0 {
        return check(
            "cgroup v2",
            Status::Fail,
            format!("statfs /sys/fs/cgroup: {}", std::io::Error::last_os_error()),
        );
    }
    if stat.f_type == CGROUP2_SUPER_MAGIC {
        check(
            "cgroup v2",
            Status::Pass,
            "unified hierarchy at /sys/fs/cgroup",
        )
    } else {
        check(
            "cgroup v2",
            Status::Fail,
            format!("unexpected filesystem type 0x{:x}", stat.f_type),
        )
    }
}

fn check_tools() -> Check {
    let mut details = Vec::new();
    let mut failed = Vec::new();
    for (program, args, label) in [
        ("nft", &["--version"][..], "nftables"),
        ("ip", &["-V"][..], "iproute2"),
    ] {
        match run_capped(program, args) {
            Ok(output) if output.status == Some(0) => {
                let first = output
                    .stdout
                    .lines()
                    .chain(output.stderr.lines())
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("")
                    .trim();
                details.push(if first.is_empty() {
                    label.to_string()
                } else {
                    first.to_string()
                });
            }
            Ok(output) => failed.push(format!(
                "{label} ({program} exited {})",
                output
                    .status
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "on timeout".to_string())
            )),
            Err(err) => failed.push(format!("{label} ({err})")),
        }
    }
    if failed.is_empty() {
        check("nftables + iproute2", Status::Pass, details.join("; "))
    } else {
        check(
            "nftables + iproute2",
            Status::Fail,
            format!("missing or broken: {}", failed.join(", ")),
        )
    }
}

fn check_daemon(socket: &Path) -> Check {
    match client::send(socket, RequestOp::Status) {
        Ok(Some(data)) => match data.get("api_version").and_then(Value::as_u64) {
            Some(version) if version == u64::from(API_VERSION) => {
                let pid = match data.get("pid").and_then(Value::as_u64) {
                    Some(pid) => format!(" pid {pid}"),
                    None => String::new(),
                };
                check(
                    "daemon",
                    Status::Pass,
                    format!("status ok, API {API_VERSION}{pid}"),
                )
            }
            Some(version) => check(
                "daemon",
                Status::Fail,
                format!("API version {version} does not match {API_VERSION}"),
            ),
            None => check("daemon", Status::Fail, "status response has no api_version"),
        },
        Ok(None) => check("daemon", Status::Fail, "daemon returned no status data"),
        Err(err) => check("daemon", Status::Fail, err.message().to_string()),
    }
}

fn load_config() -> (Config, Vec<String>) {
    let path = Path::new(client::CONFIG_PATH);
    match fs::read_to_string(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (Config::default(), Vec::new()),
        Err(err) => (
            Config::default(),
            vec![format!("read {}: {err}", path.display())],
        ),
        Ok(text) => match text.parse::<toml::Value>() {
            Ok(value) => {
                let problems = validate_config(&value);
                (client::load_config_from(path), problems)
            }
            Err(err) => (
                Config::default(),
                vec![format!("parse {}: {err}", path.display())],
            ),
        },
    }
}

/// Mirrors the daemon's config rules so doctor catches a config it would refuse.
fn validate_config(value: &toml::Value) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(root) = value.as_table() else {
        return vec!["config: root must be a table".to_string()];
    };
    for key in root.keys() {
        if key != "daemon" {
            problems.push(format!("config: unknown field `{key}`"));
        }
    }
    let Some(daemon) = root.get("daemon") else {
        return problems;
    };
    let Some(daemon) = daemon.as_table() else {
        return vec!["config: daemon must be a table".to_string()];
    };
    for key in daemon.keys() {
        if ![
            "socket_path",
            "state_path",
            "cgroup_root",
            "poll_interval_ms",
            "refresh_interval_secs",
            "max_profiles",
            "log_level",
        ]
        .contains(&key.as_str())
        {
            problems.push(format!("config: unknown field `daemon.{key}`"));
        }
    }
    for key in ["socket_path", "state_path", "cgroup_root", "log_level"] {
        if daemon
            .get(key)
            .is_some_and(|value| value.as_str().is_none())
        {
            problems.push(format!("config: daemon.{key} must be a string"));
        }
    }
    let ranges = [
        ("poll_interval_ms", 100, 10_000),
        ("refresh_interval_secs", 1, 300),
        ("max_profiles", 1, 32),
    ];
    for (key, low, high) in ranges {
        let Some(value) = daemon.get(key) else {
            continue;
        };
        match value.as_integer() {
            Some(number) if (low..=high).contains(&number) => {}
            _ => problems.push(format!(
                "config: daemon.{key} must be an integer in {low}..={high}"
            )),
        }
    }
    problems
}

fn load_state(path: &Path) -> Result<Option<State>, String> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|err| format!("parse {}: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("read {}: {err}", path.display())),
    }
}

fn check_state(
    config: &Config,
    config_problems: Vec<String>,
    state: Result<Option<&State>, &str>,
) -> Check {
    let mut problems = config_problems;
    let daemon = &config.daemon;
    if daemon.socket_path.as_os_str().is_empty() {
        problems.push("config: daemon.socket_path is empty".to_string());
    }
    if daemon.state_path.as_os_str().is_empty() {
        problems.push("config: daemon.state_path is empty".to_string());
    }
    if daemon.cgroup_root.as_os_str().is_empty() {
        problems.push("config: daemon.cgroup_root is empty".to_string());
    }
    if daemon.max_profiles == 0 || daemon.max_profiles > 32 {
        problems.push("config: daemon.max_profiles must be 1..=32".to_string());
    }
    match state {
        Err(error) => problems.push(error.to_string()),
        Ok(Some(state)) => problems.extend(validate_state(state, daemon.max_profiles)),
        Ok(None) => {}
    }
    let profiles = match &state {
        Ok(Some(state)) => state.profiles.len(),
        _ => 0,
    };
    if problems.is_empty() {
        check(
            "state + config",
            Status::Pass,
            format!("parsed, {profiles} profile(s)"),
        )
    } else {
        check("state + config", Status::Fail, problems.join("; "))
    }
}

fn validate_state(state: &State, max_profiles: u8) -> Vec<String> {
    let mut problems = Vec::new();
    if state.version != 1 {
        problems.push(format!("state version {} is not 1", state.version));
    }
    let mut indexes = std::collections::HashSet::new();
    for (id, profile) in &state.profiles {
        if !profile_id_valid(id) {
            problems.push(format!("invalid profile id '{id}'"));
        }
        if profile.id != *id {
            problems.push(format!("profile '{id}' has mismatched id '{}'", profile.id));
        }
        if profile.index >= max_profiles {
            problems.push(format!(
                "profile '{id}' index {} exceeds limit",
                profile.index
            ));
        }
        if !indexes.insert(profile.index) {
            problems.push(format!("profile '{id}' reuses index {}", profile.index));
        }
        if profile.mark != mark(profile.index)
            || profile.table != table(profile.index)
            || profile.rule_priority != rule_priority(profile.index)
        {
            problems.push(format!(
                "profile '{id}' has inconsistent mark/table/priority"
            ));
        }
        match &profile.target {
            Target::Native { path, .. } | Target::Wine { path, .. } => {
                if !path.starts_with('/') {
                    problems.push(format!("profile '{id}' target path is not absolute"));
                }
            }
            Target::Steam { app_id } if *app_id == 0 => {
                problems.push(format!("profile '{id}' has Steam app id 0"));
            }
            Target::Steam { .. } => {}
            Target::Name { name } => {
                if name.trim().is_empty() || name.contains('/') || name.contains('\\') {
                    problems.push(format!("profile '{id}' has an invalid process name"));
                }
            }
        }
        match &profile.mode {
            Mode::Filter { exceptions, .. } => {
                for cidr in exceptions {
                    if !cidr_valid(cidr) {
                        problems.push(format!("profile '{id}' has invalid CIDR '{cidr}'"));
                    }
                }
            }
            Mode::Route {
                interface,
                gateway,
                gateway6,
                ..
            } => {
                if interface.is_empty() {
                    problems.push(format!("profile '{id}' has an empty interface"));
                }
                if let Some(gateway) = gateway {
                    if gateway.parse::<IpAddr>().map_or(true, |ip| !ip.is_ipv4()) {
                        problems.push(format!("profile '{id}' has invalid IPv4 gateway"));
                    }
                }
                if let Some(gateway) = gateway6 {
                    if gateway.parse::<IpAddr>().map_or(true, |ip| !ip.is_ipv6()) {
                        problems.push(format!("profile '{id}' has invalid IPv6 gateway"));
                    }
                }
            }
        }
    }
    problems
}

fn cidr_valid(cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn check_profile_runtime(config: &Config, state: Option<&State>) -> Check {
    if unsafe { libc::geteuid() } != 0 {
        return check("profiles", Status::Skip, "requires root");
    }
    let Some(state) = state else {
        return check("profiles", Status::Skip, "state unavailable");
    };
    if state.profiles.is_empty() {
        return check("profiles", Status::Pass, "no configured profiles");
    }
    let enabled = state
        .profiles
        .values()
        .filter(|profile| profile.enabled)
        .count();
    if enabled == 0 {
        return check("profiles", Status::Pass, "no enabled profiles");
    }

    let mut problems = Vec::new();
    let cgroup =
        CgroupManager::new(config.daemon.cgroup_root.clone()).map_err(|err| err.to_string());
    let nft = NftManager::new(&config.daemon.cgroup_root).map_err(|err| err.to_string());

    for profile in state.profiles.values().filter(|profile| profile.enabled) {
        match &cgroup {
            Ok(manager) => {
                if !manager
                    .profile_path(&profile.id)
                    .join("cgroup.procs")
                    .is_file()
                {
                    problems.push(format!("{}: missing cgroup", profile.id));
                }
            }
            Err(err) => problems.push(format!("{}: cgroup root: {err}", profile.id)),
        }
        match &nft {
            Ok(manager) => match manager.exists(profile) {
                Ok(true) => {}
                Ok(false) => problems.push(format!("{}: missing nft table", profile.id)),
                Err(err) => problems.push(format!("{}: nft: {err}", profile.id)),
            },
            Err(err) => problems.push(format!("{}: nft: {err}", profile.id)),
        }
        match ip::exists(profile) {
            Ok(true) => {}
            Ok(false) => problems.push(format!("{}: missing ip rule/route", profile.id)),
            Err(err) => problems.push(format!("{}: ip: {err}", profile.id)),
        }
    }

    if problems.is_empty() {
        check(
            "profiles",
            Status::Pass,
            format!("{enabled} enabled profile(s) healthy"),
        )
    } else {
        check("profiles", Status::Fail, problems.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_versions_compare_at_major_minor() {
        assert_eq!(parse_kernel("6.12.1-arch1"), Some((6, 12)));
        assert_eq!(parse_kernel("5.13.0"), Some((5, 13)));
        assert_eq!(parse_kernel("5.12"), Some((5, 12)));
        assert_eq!(parse_kernel("garbage"), None);
        assert!(parse_kernel("6.12.1") >= Some((5, 13)));
    }

    #[test]
    fn cidr_validation_matches_address_family() {
        assert!(cidr_valid("10.0.0.0/8"));
        assert!(cidr_valid("2001:db8::/32"));
        assert!(!cidr_valid("10.0.0.0/33"));
        assert!(!cidr_valid("2001:db8::/129"));
        assert!(!cidr_valid("nope"));
    }

    #[test]
    fn state_validation_catches_inconsistent_profiles() {
        let state: State = serde_json::from_str(
            r#"{"version":1,"profiles":{"game":{"id":"game","target":{"kind":"steam","app_id":440},"target_uid":1000,"owner_uid":1000,"mode":{"kind":"filter","default":"drop","exceptions":[]},"index":0,"mark":1,"table":1,"rule_priority":1,"enabled":true,"created_at":"x","updated_at":"x"}}}"#,
        )
        .expect("state parses");
        let problems = validate_state(&state, 32);
        assert!(problems
            .iter()
            .any(|problem| problem.contains("inconsistent")));
    }
}
