use std::collections::{BTreeMap, HashMap};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use netscope_linux::cgroup::{self, AttachSource, CgroupError, CgroupManager};
use netscope_linux::fanotify::{Fanotify, FanotifyError};
use netscope_linux::ip;
use netscope_linux::nft::NftManager;
use netscope_linux::proc;
use netscope_linux::protocol::{
    AddProfile, ProfileStatus, Request, RequestOp, Response, StatusData, API_VERSION,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use netscope_linux::run;
use netscope_linux::types::{
    mark, profile_id_valid, rule_priority, table, table_name, Config, FilterDefault, Mode,
    ModeSpec, Profile, ProfileId, State, Target, TargetSpec, MAX_PROFILES,
};
use netscope_linux::watcher::{self, ExecEvent};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);

const USAGE: &str = "\
usage: netscoped [--config <path>] [--foreground] [--log-level <level>]

  --config <path>       configuration file (default /etc/netscope/config.toml)
  --foreground          run in the foreground (always true; accepted for systemd)
  --log-level <level>   tracing filter (RUST_LOG overrides)
";

#[derive(Default)]
struct Args {
    config: Option<PathBuf>,
    foreground: bool,
    log_level: Option<String>,
}

struct Rt {
    cfg: Config,
    config_path: PathBuf,
    cgroup: CgroupManager,
    nft: NftManager,
    fanotify: Option<Arc<Fanotify>>,
    fanotify_ok: AtomicBool,
    inner: Mutex<Inner>,
    shutting_down: AtomicBool,
}

struct Inner {
    state: State,
    provenance: HashMap<u32, AttachSource>,
    health: HashMap<String, bool>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = async_main().await {
        eprintln!("netscoped: {err}");
        std::process::exit(1);
    }
}

async fn async_main() -> Result<(), String> {
    let args = parse_args();
    if unsafe { libc::geteuid() } != 0 {
        return Err("must run as root".to_string());
    }

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/netscope/config.toml"));
    let mut cfg = load_config(&config_path)?;
    if let Some(level) = args.log_level.clone() {
        cfg.daemon.log_level = level;
    }
    init_tracing(&cfg.daemon.log_level);
    if args.foreground {
        debug!("foreground requested");
    }

    let mut state = load_state(&cfg.daemon.state_path)?;
    ensure_cgroup_v2()?;

    let cgroup = CgroupManager::new(cfg.daemon.cgroup_root.clone())
        .map_err(|err| format!("cgroup: {err}"))?;
    cgroup
        .ensure_root()
        .map_err(|err| format!("cgroup root: {err}"))?;
    let nft = NftManager::new(&cfg.daemon.cgroup_root).map_err(|err| format!("nft: {err}"))?;

    let fanotify = match Fanotify::new() {
        Ok(fanotify) => Some(Arc::new(fanotify)),
        Err(FanotifyError::PermissionDenied) => {
            warn!("fanotify unavailable; poll-only");
            None
        }
        Err(err) => return Err(format!("fanotify: {err:?}")),
    };

    acquire_socket(&cfg.daemon.socket_path).await?;

    let poll_interval = Duration::from_millis(cfg.daemon.poll_interval_ms);
    let refresh_interval = Duration::from_secs(cfg.daemon.refresh_interval_secs);
    let rt = Arc::new(Rt {
        cfg,
        config_path,
        cgroup,
        nft,
        fanotify_ok: AtomicBool::new(fanotify.is_some()),
        fanotify,
        inner: Mutex::new(Inner {
            state: State::default(),
            provenance: HashMap::new(),
            health: HashMap::new(),
        }),
        shutting_down: AtomicBool::new(false),
    });

    {
        let mut inner = rt.inner.lock().await;
        inner.state = std::mem::take(&mut state);
        reconcile(&rt, &mut inner)?;
    }

    let socket_path = rt.cfg.daemon.socket_path.clone();
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("socket dir {}: {err}", parent.display()))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                .map_err(|err| format!("chmod {}: {err}", parent.display()))?;
        }
    }
    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("bind {}: {err}", socket_path.display()))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660))
        .map_err(|err| format!("chmod {}: {err}", socket_path.display()))?;
    if let Err(err) = socket_owner(&socket_path) {
        warn!("socket chown failed: {err}");
    }

    let mut watcher_handle = None;
    let mut exec_handle = None;
    if let Some(fanotify) = rt.fanotify.clone() {
        let (tx, rx) = mpsc::channel(64);
        watcher_handle = Some(watcher::spawn(fanotify, tx));
        exec_handle = Some(tokio::spawn(exec_task(rx, rt.clone())));
    } else {
        info!("poll-only");
    }

    let poll_handle = tokio::spawn(poll_task(rt.clone(), poll_interval));
    let refresh_handle = tokio::spawn(refresh_task(rt.clone(), refresh_interval));
    let health_handle = tokio::spawn(health_task(rt.clone()));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|err| format!("signal: {err}"))?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|err| format!("signal: {err}"))?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        tokio::spawn(serve_connection(stream, rt.clone()));
                    }
                    Err(err) => {
                        warn!("accept failed: {err}");
                    }
                }
            }
        }
    }

    rt.shutting_down.store(true, Ordering::SeqCst);
    if let Some(fanotify) = &rt.fanotify {
        fanotify.stop();
    }
    if let Some(handle) = watcher_handle {
        let _ = timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let _ = handle.join();
            }),
        )
        .await;
    }
    poll_handle.abort();
    refresh_handle.abort();
    health_handle.abort();
    if let Some(handle) = exec_handle {
        handle.abort();
    }

    {
        let mut inner = rt.inner.lock().await;
        cleanup_all(&rt, &mut inner);
        if let Err(err) = save_state(&rt.cfg.daemon.state_path, &inner.state) {
            warn!("state: write failed: {err}");
        }
    }
    let _ = fs::remove_file(&socket_path);
    info!("stopped");
    Ok(())
}

fn parse_args() -> Args {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--config" => {
                args.config = Some(PathBuf::from(next_value(&mut argv, "--config")));
            }
            "--log-level" => {
                args.log_level = Some(next_value(&mut argv, "--log-level"));
            }
            "--foreground" => args.foreground = true,
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("netscoped {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                if let Some(value) = other.strip_prefix("--config=") {
                    args.config = Some(PathBuf::from(value));
                } else if let Some(value) = other.strip_prefix("--log-level=") {
                    args.log_level = Some(value.to_string());
                } else {
                    eprintln!("netscoped: unknown argument {other}");
                    eprint!("{USAGE}");
                    std::process::exit(2);
                }
            }
        }
    }
    args
}

fn next_value(argv: &mut impl Iterator<Item = String>, flag: &str) -> String {
    match argv.next() {
        Some(value) => value,
        None => {
            eprintln!("netscoped: {flag} requires a value");
            std::process::exit(2);
        }
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.is_empty() => EnvFilter::try_new(value),
        _ => EnvFilter::try_new(level),
    }
    .unwrap_or_else(|err| {
        eprintln!("netscoped: invalid log filter: {err}");
        EnvFilter::new("info")
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init();
}

fn load_config(path: &Path) -> Result<Config, String> {
    let mut cfg = Config::default();
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            debug!("config: {} missing; using defaults", path.display());
            return Ok(cfg);
        }
        Err(err) => return Err(format!("config: read {}: {err}", path.display())),
    };
    let value: toml::Value =
        toml::from_str(&text).map_err(|err| format!("config: parse {}: {err}", path.display()))?;
    let root = value
        .as_table()
        .ok_or_else(|| "config: root must be a table".to_string())?;
    for key in root.keys() {
        if key != "daemon" {
            return Err(format!("config: unknown field `{key}`"));
        }
    }
    if let Some(daemon) = root.get("daemon") {
        let daemon = daemon
            .as_table()
            .ok_or_else(|| "config: daemon must be a table".to_string())?;
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
                return Err(format!("config: unknown field `daemon.{key}`"));
            }
        }
        if let Some(value) = daemon.get("socket_path") {
            cfg.daemon.socket_path = PathBuf::from(config_string(value, "daemon.socket_path")?);
        }
        if let Some(value) = daemon.get("state_path") {
            cfg.daemon.state_path = PathBuf::from(config_string(value, "daemon.state_path")?);
        }
        if let Some(value) = daemon.get("cgroup_root") {
            cfg.daemon.cgroup_root = PathBuf::from(config_string(value, "daemon.cgroup_root")?);
        }
        if let Some(value) = daemon.get("poll_interval_ms") {
            cfg.daemon.poll_interval_ms = config_integer(value, "daemon.poll_interval_ms")?;
        }
        if let Some(value) = daemon.get("refresh_interval_secs") {
            cfg.daemon.refresh_interval_secs =
                config_integer(value, "daemon.refresh_interval_secs")?;
        }
        if let Some(value) = daemon.get("max_profiles") {
            let max: u64 = config_integer(value, "daemon.max_profiles")?;
            cfg.daemon.max_profiles =
                u8::try_from(max).map_err(|_| "config: daemon.max_profiles must be 1..=32")?;
        }
        if let Some(value) = daemon.get("log_level") {
            cfg.daemon.log_level = config_string(value, "daemon.log_level")?;
        }
    }
    if cfg.daemon.max_profiles == 0 || cfg.daemon.max_profiles > 32 {
        return Err("config: daemon.max_profiles must be 1..=32".to_string());
    }
    if !(100..=10_000).contains(&cfg.daemon.poll_interval_ms) {
        return Err("config: daemon.poll_interval_ms must be 100..=10000".to_string());
    }
    if !(1..=300).contains(&cfg.daemon.refresh_interval_secs) {
        return Err("config: daemon.refresh_interval_secs must be 1..=300".to_string());
    }
    Ok(cfg)
}

fn config_string(value: &toml::Value, key: &str) -> Result<String, String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("config: {key} must be a string"))
}

fn config_integer(value: &toml::Value, key: &str) -> Result<u64, String> {
    let number = value
        .as_integer()
        .ok_or_else(|| format!("config: {key} must be an integer"))?;
    u64::try_from(number).map_err(|_| format!("config: {key} must be a non-negative integer"))
}

fn load_state(path: &Path) -> Result<State, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(State::default()),
        Err(err) => return Err(format!("state: read {}: {err}", path.display())),
    };
    let state: State = match serde_json::from_str(&text) {
        Ok(state) => state,
        Err(err) => {
            let moved = corrupt_path(path);
            fs::rename(path, &moved).map_err(|rename| {
                format!(
                    "state: corrupt and cannot be moved aside ({}): {rename}",
                    err
                )
            })?;
            warn!("state: corrupt, moved to {}", moved.display());
            return Ok(State::default());
        }
    };
    if state.version != 1 {
        return Err(format!("state: unsupported version {}", state.version));
    }
    for (id, profile) in &state.profiles {
        if !profile_id_valid(id) || profile.id != *id {
            return Err(format!("state: invalid profile id `{id}`"));
        }
        if profile.index >= MAX_PROFILES
            || profile.mark != mark(profile.index)
            || profile.table != table(profile.index)
            || profile.rule_priority != rule_priority(profile.index)
        {
            return Err(format!("state: inconsistent routing identity for `{id}`"));
        }
    }
    Ok(state)
}

fn corrupt_path(path: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state.json".to_string());
    path.with_file_name(format!("{name}.corrupt-{stamp}"))
}

fn save_state(path: &Path, state: &State) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state.json".to_string());
    let tmp = path.with_file_name(format!("{name}.tmp"));
    let bytes = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn ensure_cgroup_v2() -> Result<(), String> {
    let controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if !controllers.is_file() {
        return Err("cgroup v2 not mounted at /sys/fs/cgroup".to_string());
    }
    Ok(())
}

async fn acquire_socket(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let request = "{\"id\":0,\"op\":\"status\"}\n";
            let answered = stream
                .write_all(request.as_bytes())
                .and_then(|_| {
                    let mut line = String::new();
                    let mut reader = io::BufReader::new(&stream);
                    reader.read_line(&mut line).map(|_| line)
                })
                .ok()
                .and_then(|line| serde_json::from_str::<Value>(&line).ok())
                .is_some_and(|value| value.get("ok").and_then(Value::as_bool) == Some(true));
            if answered {
                return Err("another netscoped is running".to_string());
            }
            return Err(format!(
                "control socket {} is in use but did not answer a status request",
                path.display()
            ));
        }
        Err(err)
            if err.kind() == io::ErrorKind::NotFound
                || err.kind() == io::ErrorKind::ConnectionRefused =>
        {
            fs::remove_file(path)
                .map_err(|remove| format!("stale socket {}: {remove}", path.display()))?;
        }
        Err(err) => {
            return Err(format!("control socket {}: {err}", path.display()));
        }
    }
    Ok(())
}

fn socket_owner(path: &Path) -> Result<(), String> {
    let name = CString::new("netscope").expect("static group name");
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        warn!("group netscope missing; control socket root-only");
        return Ok(());
    }
    let gid = unsafe { (*group).gr_gid };
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("socket path {} contains a NUL", path.display()))?;
    if unsafe { libc::chown(path_c.as_ptr(), 0, gid) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as libc::time_t)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&secs, &mut tm) }.is_null() {
        return "1970-01-01T00:00:00Z".to_string();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

fn reconcile(rt: &Rt, inner: &mut Inner) -> Result<(), String> {
    let dirty = restat_targets(rt, inner);
    let ids: Vec<ProfileId> = inner.state.profiles.keys().cloned().collect();
    for id in ids {
        let Some(profile) = inner.state.profiles.get(&id).cloned() else {
            continue;
        };
        let result = if profile.enabled {
            reconcile_enabled(rt, &profile)
        } else {
            reconcile_disabled(rt, inner, &profile)
        };
        match result {
            Ok(healthy) => {
                inner.health.insert(id.clone(), healthy);
            }
            Err(err) => {
                inner.health.insert(id.clone(), false);
                warn!("reconcile profile={id} error={err}");
            }
        }
    }

    reconcile_orphan_cgroups(rt, inner);
    reconcile_orphan_nft(rt, inner);
    reconcile_orphan_ip(inner);
    attach_matches(rt, inner);

    if dirty > 0 {
        save_state(&rt.cfg.daemon.state_path, &inner.state)
            .map_err(|err| format!("state: write failed: {err}"))?;
    }
    Ok(())
}

fn reconcile_enabled(rt: &Rt, profile: &Profile) -> Result<bool, String> {
    if !rt.cgroup.root().join(&profile.id).is_dir() {
        rt.cgroup
            .ensure_profile(&profile.id)
            .map_err(|err| err.to_string())?;
        info!("cgroup recreated profile={}", profile.id);
    }
    rt.nft.apply(profile).map_err(|err| err.to_string())?;
    if matches!(profile.mode, Mode::Route { .. }) {
        ip::ensure(profile).map_err(|err| err.to_string())?;
    }
    let mut healthy = true;
    if fanotify_active(rt) {
        if let Err(err) = add_target_mark(rt, profile) {
            warn!("fanotify mark profile={} error={err:?}", profile.id);
            healthy = false;
        }
    }
    Ok(healthy)
}

fn reconcile_disabled(rt: &Rt, inner: &mut Inner, profile: &Profile) -> Result<bool, String> {
    if fanotify_active(rt) {
        remove_target_mark(rt, profile);
    }
    rt.nft.remove(profile).map_err(|err| err.to_string())?;
    if matches!(profile.mode, Mode::Route { .. }) {
        ip::remove(profile).map_err(|err| err.to_string())?;
    }
    let pids = rt.cgroup.procs(&profile.id).unwrap_or_default();
    rt.cgroup
        .drain(&profile.id)
        .map_err(|err| err.to_string())?;
    for pid in pids {
        inner.provenance.remove(&pid);
    }
    Ok(true)
}

fn reconcile_orphan_cgroups(rt: &Rt, inner: &mut Inner) {
    let Ok(entries) = fs::read_dir(rt.cgroup.root()) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if inner.state.profiles.contains_key(&name) {
            continue;
        }
        match rt.cgroup.remove(&name) {
            Ok(()) => info!("orphan cgroup removed {}", entry.path().display()),
            Err(err) => warn!("orphan cgroup {} error={err}", entry.path().display()),
        }
    }
}

fn reconcile_orphan_nft(rt: &Rt, inner: &mut Inner) {
    let names: Vec<String> = inner
        .state
        .profiles
        .values()
        .filter(|profile| profile.enabled)
        .map(|profile| table_name(&profile.mode, &profile.id))
        .collect();
    let tables = match rt.nft.list_tables() {
        Ok(tables) => tables,
        Err(err) => {
            warn!("nft list tables error={err}");
            return;
        }
    };
    for name in tables {
        if !(name.starts_with("netscope_filter_") || name.starts_with("netscope_route_")) {
            continue;
        }
        if names.iter().any(|expected| expected == &name) {
            continue;
        }
        match run("nft", &["delete", "table", "inet", &name], None) {
            Ok(_) => info!("orphan nft table removed {name}"),
            Err(err) => warn!("orphan nft table {name} error={err}"),
        }
    }
}

#[derive(Clone, Copy)]
struct IpRule {
    family: i32,
    mark: u32,
    table: u32,
    priority: u32,
}

fn reconcile_orphan_ip(inner: &mut Inner) {
    let used: Vec<u32> = inner
        .state
        .profiles
        .values()
        .filter(|profile| matches!(profile.mode, Mode::Route { .. }))
        .map(|profile| profile.table)
        .collect();
    let rules = match ip_rules() {
        Ok(rules) => rules,
        Err(err) => {
            warn!("ip rule show error={err}");
            return;
        }
    };
    let mut flushed: Vec<(i32, u32)> = Vec::new();
    for rule in rules {
        if !(20000..=20031).contains(&rule.table) || used.contains(&rule.table) {
            continue;
        }
        let flag = if rule.family == 6 { "-6" } else { "-4" };
        let mark_arg = format!("0x{:x}", rule.mark);
        let table_arg = rule.table.to_string();
        let priority_arg = rule.priority.to_string();
        let _ = run(
            "ip",
            &[
                flag,
                "rule",
                "del",
                "fwmark",
                &mark_arg,
                "table",
                &table_arg,
                "pref",
                &priority_arg,
            ],
            None,
        );
        let key = (rule.family, rule.table);
        if !flushed.contains(&key) {
            let _ = run("ip", &[flag, "route", "flush", "table", &table_arg], None);
            flushed.push(key);
            info!("orphan ip rule removed table={}", rule.table);
        }
    }
}

fn ip_rules() -> Result<Vec<IpRule>, String> {
    let mut rules = Vec::new();
    for family in [4, 6] {
        let flag = if family == 6 { "-6" } else { "-4" };
        let output =
            run("ip", &[flag, "-j", "rule", "show"], None).map_err(|err| err.to_string())?;
        let value: Value = serde_json::from_slice(&output.stdout).map_err(|err| err.to_string())?;
        let Some(entries) = value.as_array() else {
            continue;
        };
        for entry in entries {
            let Some(mark) = entry
                .get("fwmark")
                .and_then(value_u32)
                .or_else(|| entry.get("mark").and_then(value_u32))
            else {
                continue;
            };
            let Some(table) = entry.get("table").and_then(value_u32) else {
                continue;
            };
            let Some(priority) = entry
                .get("priority")
                .and_then(value_u32)
                .or_else(|| entry.get("pref").and_then(value_u32))
            else {
                continue;
            };
            rules.push(IpRule {
                family,
                mark,
                table,
                priority,
            });
        }
    }
    Ok(rules)
}

fn value_u32(value: &Value) -> Option<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).ok();
    }
    let text = value.as_str()?;
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn attach_matches(rt: &Rt, inner: &mut Inner) {
    let profiles: Vec<Profile> = inner
        .state
        .profiles
        .values()
        .filter(|profile| profile.enabled)
        .cloned()
        .collect();
    let mut matches = proc::scan_native(&profiles);
    matches.extend(proc::scan_steam(&profiles));
    matches.extend(proc::scan_wine(&profiles));
    for (id, pid) in matches {
        attach_one(rt, inner, &id, pid, AttachSource::Late);
    }
}

fn attach_one(rt: &Rt, inner: &mut Inner, id: &str, pid: u32, source: AttachSource) {
    let Some(profile) = inner.state.profiles.get(id) else {
        return;
    };
    if !profile.enabled {
        return;
    }
    if rt
        .cgroup
        .procs(id)
        .map(|pids| pids.contains(&pid))
        .unwrap_or(false)
    {
        return;
    }
    match rt.cgroup.attach_tree(pid, id, source) {
        Ok(attached) => {
            for tgid in attached {
                inner.provenance.insert(tgid, source);
            }
            info!("attach profile={id} pid={pid} source=poll");
        }
        Err(CgroupError::ProcessGone(_)) => {}
        Err(err) => warn!("attach profile={id} pid={pid} error={err}"),
    }
}

fn restat_targets(rt: &Rt, inner: &mut Inner) -> usize {
    let ids: Vec<ProfileId> = inner.state.profiles.keys().cloned().collect();
    let mut changed = 0usize;
    for id in ids {
        let Some(profile) = inner.state.profiles.get(&id) else {
            continue;
        };
        let is_wine = matches!(&profile.target, Target::Wine { .. });
        let (path, old_dev, old_ino) = match &profile.target {
            Target::Native { path, dev, ino } | Target::Wine { path, dev, ino } => {
                (path.clone(), *dev, *ino)
            }
            Target::Steam { .. } => continue,
        };
        let enabled = profile.enabled;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                if enabled {
                    warn!("executable missing profile={id} path={path}");
                }
                continue;
            }
        };
        if metadata.dev() == old_dev && metadata.ino() == old_ino {
            continue;
        }
        if fanotify_active(rt) {
            remove_target_mark(rt, profile);
        }
        if let Some(profile) = inner.state.profiles.get_mut(&id) {
            profile.target = if is_wine {
                Target::Wine {
                    path: path.clone(),
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                }
            } else {
                Target::Native {
                    path: path.clone(),
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                }
            };
            profile.updated_at = now_rfc3339();
        }
        if fanotify_active(rt) {
            if let Some(profile) = inner.state.profiles.get(&id) {
                if let Err(err) = add_target_mark(rt, profile) {
                    warn!("fanotify mark profile={id} error={err:?}");
                }
            }
        }
        changed += 1;
        info!("target updated profile={id} path={path}");
    }
    changed
}

fn health_tick(rt: &Rt, inner: &mut Inner) {
    let ids: Vec<ProfileId> = inner.state.profiles.keys().cloned().collect();
    for id in ids {
        let Some(profile) = inner.state.profiles.get(&id).cloned() else {
            continue;
        };
        if !profile.enabled {
            inner.health.insert(id, true);
            continue;
        }
        let mut healthy = true;
        if !rt.cgroup.root().join(&id).is_dir() {
            if let Err(err) = rt.cgroup.ensure_profile(&id) {
                warn!("health profile={id} cgroup error={err}");
                healthy = false;
            } else {
                info!("health repaired profile={id} component=cgroup");
            }
            match rt.nft.apply(&profile) {
                Ok(()) => info!("health repaired profile={id} component=nft"),
                Err(err) => {
                    warn!("health profile={id} nft error={err}");
                    healthy = false;
                }
            }
        }
        match rt.nft.exists(&profile) {
            Ok(true) => {}
            Ok(false) => match rt.nft.apply(&profile) {
                Ok(()) => info!("health repaired profile={id} component=nft"),
                Err(err) => {
                    warn!("health profile={id} nft error={err}");
                    healthy = false;
                }
            },
            Err(err) => {
                warn!("health profile={id} nft error={err}");
                healthy = false;
            }
        }
        if matches!(profile.mode, Mode::Route { .. }) {
            match ip::exists(&profile) {
                Ok(true) => {}
                Ok(false) => match ip::ensure(&profile) {
                    Ok(()) => info!("health repaired profile={id} component=ip"),
                    Err(err) => {
                        warn!("health profile={id} ip error={err}");
                        healthy = false;
                    }
                },
                Err(err) => {
                    warn!("health profile={id} ip error={err}");
                    healthy = false;
                }
            }
        }
        if fanotify_active(rt) {
            if let Err(err) = add_target_mark(rt, &profile) {
                warn!("health profile={id} fanotify error={err:?}");
                healthy = false;
            }
        }
        if healthy {
            healthy = rt.cgroup.root().join(&id).is_dir()
                && rt.nft.exists(&profile).unwrap_or(false)
                && ip::exists(&profile).unwrap_or(false);
        }
        inner.health.insert(id, healthy);
    }
    let mut live = std::collections::HashSet::new();
    for profile in inner.state.profiles.values() {
        live.extend(rt.cgroup.procs(&profile.id).unwrap_or_default());
    }
    inner.provenance.retain(|pid, _| live.contains(pid));
}

async fn poll_task(rt: Arc<Rt>, period: Duration) {
    let mut ticker = interval(period);
    loop {
        ticker.tick().await;
        if rt.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let mut inner = rt.inner.lock().await;
        attach_matches(&rt, &mut inner);
    }
}

async fn refresh_task(rt: Arc<Rt>, period: Duration) {
    let mut ticker = interval(period);
    loop {
        ticker.tick().await;
        if rt.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let mut inner = rt.inner.lock().await;
        let changed = restat_targets(&rt, &mut inner);
        if changed > 0 {
            if let Err(err) = save_state(&rt.cfg.daemon.state_path, &inner.state) {
                warn!("state: write failed: {err}");
            }
        }
        attach_matches(&rt, &mut inner);
    }
}

async fn health_task(rt: Arc<Rt>) {
    let mut ticker = interval(HEALTH_INTERVAL);
    loop {
        ticker.tick().await;
        if rt.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let mut inner = rt.inner.lock().await;
        health_tick(&rt, &mut inner);
    }
}

async fn exec_task(mut rx: mpsc::Receiver<ExecEvent>, rt: Arc<Rt>) {
    while let Some(event) = rx.recv().await {
        handle_exec(&rt, event).await;
    }
    rt.fanotify_ok.store(false, Ordering::SeqCst);
    if !rt.shutting_down.load(Ordering::SeqCst) {
        warn!("fanotify disabled; poll-only");
    }
    let inner = rt.inner.lock().await;
    for profile in inner.state.profiles.values() {
        if profile.enabled {
            remove_target_mark(&rt, profile);
        }
    }
}

async fn handle_exec(rt: &Rt, event: ExecEvent) {
    let ExecEvent {
        pid,
        mask,
        dev,
        ino,
        reply,
        overflow,
        ..
    } = event;
    if overflow {
        warn!("fanotify queue overflow; rescanning");
        let mut inner = rt.inner.lock().await;
        attach_matches(rt, &mut inner);
        drop(inner);
        let _ = reply.send(true);
        return;
    }
    let mut inner = rt.inner.lock().await;
    let profile = inner
        .state
        .profiles
        .values()
        .find(|profile| {
            if !profile.enabled {
                return false;
            }
            match &profile.target {
                Target::Native {
                    dev: event_dev,
                    ino: event_ino,
                    ..
                } => mask & libc::FAN_OPEN_EXEC_PERM != 0 && *event_dev == dev && *event_ino == ino,
                Target::Wine {
                    dev: event_dev,
                    ino: event_ino,
                    ..
                } => mask & libc::FAN_OPEN_PERM != 0 && *event_dev == dev && *event_ino == ino,
                Target::Steam { .. } => false,
            }
        })
        .cloned();
    let allow = match profile {
        None => true,
        Some(profile) => {
            let source = if matches!(&profile.target, Target::Wine { .. }) {
                AttachSource::PreOpen
            } else {
                AttachSource::PreExec
            };
            if source == AttachSource::PreOpen {
                // wineserver often opens the PE before the game process has
                // its command line; never scope the shared server, attach the
                // process that is actually running the selected PE.
                let mut pids = Vec::new();
                if proc::wine_pid_matches(&profile, pid) {
                    pids.push(pid);
                } else {
                    pids.extend(
                        proc::scan_wine(std::slice::from_ref(&profile))
                            .into_iter()
                            .map(|(_, pid)| pid),
                    );
                }
                pids.sort_unstable();
                pids.dedup();
                if pids.is_empty() {
                    true
                } else {
                    pids.into_iter()
                        .all(|pid| attach_event(rt, &mut inner, &profile, pid, source))
                }
            } else {
                attach_event(rt, &mut inner, &profile, pid, source)
            }
        }
    };
    drop(inner);
    let _ = reply.send(allow);
}

fn attach_event(
    rt: &Rt,
    inner: &mut Inner,
    profile: &Profile,
    pid: u32,
    source: AttachSource,
) -> bool {
    if rt
        .cgroup
        .procs(&profile.id)
        .map(|pids| pids.contains(&pid))
        .unwrap_or(false)
    {
        return true;
    }
    match cgroup::read_uid(pid) {
        None => true,
        Some(uid) if uid != profile.target_uid => true,
        Some(_) => match rt.cgroup.attach_pid(&profile.id, pid, source) {
            Ok(outcome) => {
                inner.provenance.insert(outcome.tgid, source);
                info!(
                    "attach profile={} pid={pid} source={}",
                    profile.id,
                    if source == AttachSource::PreOpen {
                        "pre-open"
                    } else {
                        "pre-exec"
                    }
                );
                true
            }
            Err(CgroupError::ProcessGone(_)) => true,
            Err(err) => {
                warn!("attach failed profile={} pid={pid} error={err}", profile.id);
                false
            }
        },
    }
}

async fn read_line_limited<R>(reader: &mut R, limit: usize) -> io::Result<Option<(Vec<u8>, bool)>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let mut too_large = false;
    loop {
        let (take, found_newline, empty) = {
            let buf = reader.fill_buf().await?;
            if buf.is_empty() {
                (0, false, true)
            } else {
                let newline = buf.iter().position(|byte| *byte == b'\n');
                let take = newline.map_or(buf.len(), |position| position + 1);
                if !too_large {
                    if line.len() + take > limit + 1 {
                        too_large = true;
                        line.clear();
                    } else {
                        line.extend_from_slice(&buf[..take]);
                    }
                }
                (take, newline.is_some(), false)
            }
        };
        if empty {
            return if line.is_empty() && !too_large {
                Ok(None)
            } else {
                Ok(Some((line, too_large)))
            };
        }
        reader.consume(take);
        if found_newline {
            return Ok(Some((line, too_large)));
        }
    }
}

async fn serve_connection(stream: UnixStream, rt: Arc<Rt>) {
    let peer_uid = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        Err(err) => {
            warn!("peer credentials: {err}");
            return;
        }
    };
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut closing = false;

    loop {
        let read = timeout(
            REQUEST_TIMEOUT,
            read_line_limited(&mut reader, MAX_REQUEST_BYTES),
        )
        .await;
        let (mut line, too_large) = match read {
            Err(_) => {
                let response = Response::err(0, "request timeout");
                let _ = write_response(&mut writer, &response).await;
                break;
            }
            Ok(Err(err)) => {
                debug!("connection read error: {err}");
                break;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(pair))) => pair,
        };
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if too_large || line.len() > MAX_REQUEST_BYTES {
            let response = Response::err(0, "request too large");
            if write_response(&mut writer, &response).await.is_err() {
                break;
            }
            if closing {
                break;
            }
            closing = true;
            continue;
        }

        let value: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(err) => {
                let response = Response::err(0, format!("invalid json: {err}"));
                if write_response(&mut writer, &response).await.is_err() {
                    break;
                }
                if closing {
                    break;
                }
                closing = true;
                continue;
            }
        };
        let request_id = value.get("id").and_then(Value::as_u64).unwrap_or(0);
        let request: Request = match serde_json::from_value(value) {
            Ok(request) => request,
            Err(err) => {
                let response = Response::err(request_id, format!("invalid request: {err}"));
                if write_response(&mut writer, &response).await.is_err() {
                    break;
                }
                if closing {
                    break;
                }
                closing = true;
                continue;
            }
        };

        let response = handle_request(&rt, peer_uid, request).await;
        if write_response(&mut writer, &response).await.is_err() {
            break;
        }
        if closing {
            break;
        }
    }
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &Response,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        bytes = serde_json::to_vec(&Response::err(response.id, "response too large"))
            .map_err(io::Error::other)?;
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

async fn handle_request(rt: &Arc<Rt>, peer_uid: u32, request: Request) -> Response {
    let id = request.id;
    match request.op {
        RequestOp::Status => match status_data(rt).await {
            Ok(data) => Response::ok(id, json!(data)),
            Err(err) => Response::err(id, err),
        },
        RequestOp::List => match list_profiles(rt).await {
            Ok(profiles) => Response::ok(id, json!(profiles)),
            Err(err) => Response::err(id, err),
        },
        RequestOp::Add(add) => match add_profile(rt, peer_uid, add).await {
            Ok(profile) => Response::ok(id, json!(profile)),
            Err(err) => Response::err(id, err),
        },
        RequestOp::Remove { name: profile_id } => {
            match remove_profile(rt, peer_uid, &profile_id).await {
                Ok(()) => Response::ok(id, json!({ "removed": profile_id })),
                Err(err) => Response::err(id, err),
            }
        }
        RequestOp::Enable { name: profile_id } => {
            match set_enabled(rt, peer_uid, &profile_id, true).await {
                Ok(profile) => Response::ok(id, json!(profile)),
                Err(err) => Response::err(id, err),
            }
        }
        RequestOp::Disable { name: profile_id } => {
            match set_enabled(rt, peer_uid, &profile_id, false).await {
                Ok(profile) => Response::ok(id, json!(profile)),
                Err(err) => Response::err(id, err),
            }
        }
        RequestOp::Refresh => match refresh_all(rt).await {
            Ok(updated) => Response::ok(id, json!({ "updated": updated })),
            Err(err) => Response::err(id, err),
        },
    }
}

async fn status_data(rt: &Arc<Rt>) -> Result<StatusData, String> {
    let inner = rt.inner.lock().await;
    let profiles = inner
        .state
        .profiles
        .values()
        .map(|profile| profile_status(rt, &inner, profile))
        .collect();
    Ok(StatusData {
        api_version: API_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        kernel: kernel_release(),
        cgroup_root: rt.cfg.daemon.cgroup_root.display().to_string(),
        state_path: rt.cfg.daemon.state_path.display().to_string(),
        config_path: rt.config_path.display().to_string(),
        profiles,
    })
}

async fn list_profiles(rt: &Arc<Rt>) -> Result<Vec<ProfileStatus>, String> {
    let inner = rt.inner.lock().await;
    Ok(inner
        .state
        .profiles
        .values()
        .map(|profile| profile_status(rt, &inner, profile))
        .collect())
}

fn profile_status(rt: &Rt, inner: &Inner, profile: &Profile) -> ProfileStatus {
    let mut pids = rt.cgroup.procs(&profile.id).unwrap_or_default();
    pids.sort_unstable();
    pids.dedup();
    let mut pre_exec = false;
    let mut pre_open = false;
    let mut late = false;
    for pid in &pids {
        match inner.provenance.get(pid) {
            Some(AttachSource::PreExec) => pre_exec = true,
            Some(AttachSource::PreOpen) => pre_open = true,
            Some(AttachSource::Late) => late = true,
            None => {}
        }
    }
    let attached = match (pre_exec || pre_open, late) {
        (true, true) => "mixed",
        (true, false) if pre_exec => "pre-exec",
        (true, false) => "pre-open",
        (false, true) => "late",
        (false, false) => "none",
    }
    .to_string();
    let healthy = inner
        .health
        .get(&profile.id)
        .copied()
        .unwrap_or(!profile.enabled);
    let mut warnings = Vec::new();
    if profile.enabled && !healthy {
        warnings.push("profile unhealthy; run: sudo netscope doctor".to_string());
    }
    if let Target::Native { path, .. } | Target::Wine { path, .. } = &profile.target {
        if !fanotify_active(rt) {
            warnings.push("fanotify unavailable; poll-only".to_string());
        }
        if !Path::new(path).exists() {
            warnings.push("executable missing".to_string());
        }
    }
    ProfileStatus {
        id: profile.id.clone(),
        mode: match &profile.mode {
            Mode::Filter { .. } => "filter".to_string(),
            Mode::Route { .. } => "route".to_string(),
        },
        enabled: profile.enabled,
        target: match &profile.target {
            Target::Native { path, .. } => path.clone(),
            Target::Wine { path, .. } => format!("wine:{path}"),
            Target::Steam { app_id } => format!("steam:{app_id}"),
        },
        cgroup: rt.cgroup.root().join(&profile.id).display().to_string(),
        pids,
        nft_table: format!("inet {}", table_name(&profile.mode, &profile.id)),
        mark: format!("0x{:x}", profile.mark),
        table: profile.table,
        rule_priority: profile.rule_priority,
        attached,
        healthy,
        warnings,
    }
}

fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

async fn add_profile(
    rt: &Arc<Rt>,
    peer_uid: u32,
    add: AddProfile,
) -> Result<ProfileStatus, String> {
    if peer_uid != 0 && add.target_uid != peer_uid {
        return Err("permission denied: target_uid must match your uid".to_string());
    }
    let mode = validate_mode(&add.mode)?;
    let target = resolve_target(&add.target)?;

    let mut inner = rt.inner.lock().await;
    if rt.shutting_down.load(Ordering::SeqCst) {
        return Err("daemon shutting down".to_string());
    }
    if !profile_id_valid(&add.name) {
        return Err(format!("invalid profile id `{}`", add.name));
    }
    if inner.state.profiles.contains_key(&add.name) {
        return Err(format!("profile {} already exists", add.name));
    }
    if inner.state.profiles.len() >= usize::from(rt.cfg.daemon.max_profiles) {
        return Err(format!(
            "profile limit reached ({})",
            rt.cfg.daemon.max_profiles
        ));
    }
    if let Some(existing) = duplicate_target(&inner.state.profiles, &target) {
        return Err(format!("target already scoped by profile {existing}"));
    }
    let index = ip::allocate_index(&inner.state.profiles, rt.cfg.daemon.max_profiles)
        .map_err(|err| err.to_string())?;
    if matches!(mode, Mode::Route { .. }) {
        let route_table = table(index);
        if ip::table_in_use(route_table).map_err(|err| err.to_string())? {
            return Err(format!("table {route_table} already in use"));
        }
    }

    let now = now_rfc3339();
    let profile = Profile {
        id: add.name.clone(),
        target,
        target_uid: add.target_uid,
        owner_uid: peer_uid,
        mode,
        index,
        mark: mark(index),
        table: table(index),
        rule_priority: rule_priority(index),
        enabled: true,
        created_at: now.clone(),
        updated_at: now,
    };

    if let Err(err) = apply_profile(rt, &profile) {
        rollback_profile(rt, &profile);
        return Err(err);
    }
    inner
        .state
        .profiles
        .insert(profile.id.clone(), profile.clone());
    if let Err(err) = save_state(&rt.cfg.daemon.state_path, &inner.state) {
        inner.state.profiles.remove(&profile.id);
        rollback_profile(rt, &profile);
        return Err(format!("state: write failed: {err}"));
    }
    inner.health.insert(profile.id.clone(), true);
    attach_matches(rt, &mut inner);
    Ok(profile_status(rt, &inner, &profile))
}

fn apply_profile(rt: &Rt, profile: &Profile) -> Result<(), String> {
    rt.cgroup
        .ensure_profile(&profile.id)
        .map_err(|err| err.to_string())?;
    rt.nft.apply(profile).map_err(|err| err.to_string())?;
    if matches!(profile.mode, Mode::Route { .. }) {
        ip::ensure(profile).map_err(|err| err.to_string())?;
    }
    if fanotify_active(rt) {
        add_target_mark(rt, profile).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn rollback_profile(rt: &Rt, profile: &Profile) {
    if matches!(profile.mode, Mode::Route { .. }) {
        let _ = ip::remove(profile);
    }
    let _ = rt.nft.remove(profile);
    remove_target_mark(rt, profile);
    let _ = rt.cgroup.remove(&profile.id);
}

fn add_target_mark(rt: &Rt, profile: &Profile) -> Result<(), FanotifyError> {
    let Some(fanotify) = &rt.fanotify else {
        return Ok(());
    };
    match &profile.target {
        Target::Native { path, .. } => fanotify.add_exec_mark(Path::new(path)),
        Target::Wine { path, .. } => fanotify.add_open_mark(Path::new(path)),
        Target::Steam { .. } => Ok(()),
    }
}

fn remove_target_mark(rt: &Rt, profile: &Profile) {
    let Some(fanotify) = &rt.fanotify else {
        return;
    };
    let result = match &profile.target {
        Target::Native { path, .. } => fanotify.remove_exec_mark(Path::new(path)),
        Target::Wine { path, .. } => fanotify.remove_open_mark(Path::new(path)),
        Target::Steam { .. } => Ok(()),
    };
    if let Err(err) = result {
        debug!("fanotify unmark profile={} error={err:?}", profile.id);
    }
}

async fn remove_profile(rt: &Arc<Rt>, peer_uid: u32, id: &str) -> Result<(), String> {
    let mut inner = rt.inner.lock().await;
    if rt.shutting_down.load(Ordering::SeqCst) {
        return Err("daemon shutting down".to_string());
    }
    let profile = inner
        .state
        .profiles
        .get(id)
        .cloned()
        .ok_or_else(|| format!("profile {id} not found"))?;
    require_owner(peer_uid, &profile)?;

    if profile.enabled {
        if let Some(stored) = inner.state.profiles.get_mut(id) {
            stored.enabled = false;
            stored.updated_at = now_rfc3339();
        }
        save_state(&rt.cfg.daemon.state_path, &inner.state)
            .map_err(|err| format!("state: write failed: {err}"))?;
    }
    remove_target_mark(rt, &profile);
    if let Err(err) = rt.nft.remove(&profile) {
        warn!("remove profile={id} nft error={err}");
    }
    if matches!(profile.mode, Mode::Route { .. }) {
        if let Err(err) = ip::remove(&profile) {
            warn!("remove profile={id} ip error={err}");
        }
    }
    let pids = rt.cgroup.procs(id).unwrap_or_default();
    if let Err(err) = rt.cgroup.remove(id) {
        warn!("remove profile={id} cgroup error={err}");
    }
    for pid in pids {
        inner.provenance.remove(&pid);
    }
    inner.state.profiles.remove(id);
    inner.health.remove(id);
    save_state(&rt.cfg.daemon.state_path, &inner.state)
        .map_err(|err| format!("state: write failed: {err}"))?;
    Ok(())
}

async fn set_enabled(
    rt: &Arc<Rt>,
    peer_uid: u32,
    id: &str,
    enabled: bool,
) -> Result<ProfileStatus, String> {
    let mut inner = rt.inner.lock().await;
    if rt.shutting_down.load(Ordering::SeqCst) {
        return Err("daemon shutting down".to_string());
    }
    let profile = inner
        .state
        .profiles
        .get(id)
        .cloned()
        .ok_or_else(|| format!("profile {id} not found"))?;
    require_owner(peer_uid, &profile)?;

    if enabled {
        if let Err(err) = apply_profile(rt, &profile) {
            rollback_profile(rt, &profile);
            return Err(err);
        }
        if let Some(stored) = inner.state.profiles.get_mut(id) {
            stored.enabled = true;
            stored.updated_at = now_rfc3339();
        }
        if let Err(err) = save_state(&rt.cfg.daemon.state_path, &inner.state) {
            remove_target_mark(rt, &profile);
            let _ = rt.nft.remove(&profile);
            if matches!(profile.mode, Mode::Route { .. }) {
                let _ = ip::remove(&profile);
            }
            let _ = rt.cgroup.drain(id);
            if let Some(stored) = inner.state.profiles.get_mut(id) {
                stored.enabled = false;
            }
            return Err(format!("state: write failed: {err}"));
        }
        inner.health.insert(id.to_string(), true);
        attach_matches(rt, &mut inner);
    } else {
        remove_target_mark(rt, &profile);
        if let Err(err) = rt.nft.remove(&profile) {
            warn!("disable profile={id} nft error={err}");
        }
        if matches!(profile.mode, Mode::Route { .. }) {
            if let Err(err) = ip::remove(&profile) {
                warn!("disable profile={id} ip error={err}");
            }
        }
        let pids = rt.cgroup.procs(id).unwrap_or_default();
        if let Err(err) = rt.cgroup.drain(id) {
            warn!("disable profile={id} drain error={err}");
        }
        for pid in pids {
            inner.provenance.remove(&pid);
        }
        if let Some(stored) = inner.state.profiles.get_mut(id) {
            stored.enabled = false;
            stored.updated_at = now_rfc3339();
        }
        save_state(&rt.cfg.daemon.state_path, &inner.state)
            .map_err(|err| format!("state: write failed: {err}"))?;
        inner.health.insert(id.to_string(), true);
    }
    let stored = inner
        .state
        .profiles
        .get(id)
        .cloned()
        .ok_or_else(|| format!("profile {id} not found"))?;
    Ok(profile_status(rt, &inner, &stored))
}

async fn refresh_all(rt: &Arc<Rt>) -> Result<usize, String> {
    let mut inner = rt.inner.lock().await;
    if rt.shutting_down.load(Ordering::SeqCst) {
        return Err("daemon shutting down".to_string());
    }
    let changed = restat_targets(rt, &mut inner);
    if changed > 0 {
        save_state(&rt.cfg.daemon.state_path, &inner.state)
            .map_err(|err| format!("state: write failed: {err}"))?;
    }
    attach_matches(rt, &mut inner);
    Ok(changed)
}

fn require_owner(peer_uid: u32, profile: &Profile) -> Result<(), String> {
    if peer_uid == 0 || peer_uid == profile.owner_uid {
        Ok(())
    } else {
        Err(format!(
            "permission denied: profile owned by uid {}",
            profile.owner_uid
        ))
    }
}

fn validate_mode(spec: &ModeSpec) -> Result<Mode, String> {
    match spec {
        ModeSpec::Filter {
            default,
            allow_cidrs,
            deny_cidrs,
        } => {
            match default {
                FilterDefault::Drop => {
                    if !deny_cidrs.is_empty() {
                        return Err("filter drop accepts allow_cidrs, not deny_cidrs".to_string());
                    }
                    for cidr in allow_cidrs {
                        parse_cidr(cidr)?;
                    }
                }
                FilterDefault::Allow => {
                    if !allow_cidrs.is_empty() {
                        return Err("filter allow accepts deny_cidrs, not allow_cidrs".to_string());
                    }
                    if deny_cidrs.is_empty() {
                        return Err("filter allow requires at least one deny cidr".to_string());
                    }
                    for cidr in deny_cidrs {
                        parse_cidr(cidr)?;
                    }
                }
            }
            let exceptions = match default {
                FilterDefault::Drop => allow_cidrs.clone(),
                FilterDefault::Allow => deny_cidrs.clone(),
            };
            Ok(Mode::Filter {
                default: *default,
                exceptions,
            })
        }
        ModeSpec::Route {
            interface,
            gateway,
            gateway6,
            include_lan,
            allow_ipv6,
        } => {
            if interface.is_empty()
                || interface.contains('/')
                || interface == "."
                || interface == ".."
            {
                return Err(format!("invalid interface `{interface}`"));
            }
            let sysfs = Path::new("/sys/class/net").join(interface);
            if !sysfs.is_dir() {
                run("ip", &["link", "show", "dev", interface], None)
                    .map_err(|_| format!("interface {interface} does not exist"))?;
            }
            if let Some(gateway) = gateway {
                gateway
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| format!("invalid IPv4 gateway {gateway}"))?;
            }
            if let Some(gateway6) = gateway6 {
                if !*allow_ipv6 {
                    return Err("gateway6 requires allow_ipv6".to_string());
                }
                gateway6
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|_| format!("invalid IPv6 gateway {gateway6}"))?;
            }
            Ok(Mode::Route {
                interface: interface.clone(),
                gateway: gateway.clone(),
                gateway6: gateway6.clone(),
                include_lan: *include_lan,
                allow_ipv6: *allow_ipv6,
            })
        }
    }
}

fn parse_cidr(text: &str) -> Result<(), String> {
    let (address, prefix) = text
        .split_once('/')
        .ok_or_else(|| format!("invalid cidr {text}"))?;
    let address: std::net::IpAddr = address
        .parse()
        .map_err(|_| format!("invalid cidr {text}"))?;
    let prefix: u8 = prefix.parse().map_err(|_| format!("invalid cidr {text}"))?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(format!("invalid cidr {text}"));
    }
    Ok(())
}

fn resolve_target(spec: &TargetSpec) -> Result<Target, String> {
    match spec {
        TargetSpec::Steam { app_id } => {
            if *app_id == 0 {
                return Err("steam app id must be non-zero".to_string());
            }
            Ok(Target::Steam { app_id: *app_id })
        }
        TargetSpec::Native { path } => {
            if !Path::new(path).is_absolute() {
                return Err(format!("target {path} must be an absolute path"));
            }
            let canonical =
                fs::canonicalize(path).map_err(|err| format!("invalid target {path}: {err}"))?;
            reject_daemon_tool(&canonical)?;
            let metadata =
                fs::metadata(&canonical).map_err(|err| format!("invalid target {path}: {err}"))?;
            if !metadata.is_file() {
                return Err(format!("target {path} is not a file"));
            }
            let mut head = [0u8; 4];
            File::open(&canonical)
                .and_then(|mut file| file.read_exact(&mut head))
                .map_err(|err| format!("invalid target {path}: {err}"))?;
            if &head != b"\x7fELF" {
                return Err(format!("target {path} is not an ELF executable"));
            }
            let canonical_path = canonical
                .to_str()
                .ok_or_else(|| format!("target {path} is not valid UTF-8"))?;
            Ok(Target::Native {
                path: canonical_path.to_string(),
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        }
        TargetSpec::Wine { path } => {
            if !Path::new(path).is_absolute() {
                return Err(format!("target {path} must be an absolute path"));
            }
            let canonical =
                fs::canonicalize(path).map_err(|err| format!("invalid target {path}: {err}"))?;
            reject_daemon_tool(&canonical)?;
            let metadata =
                fs::metadata(&canonical).map_err(|err| format!("invalid target {path}: {err}"))?;
            if !metadata.is_file() {
                return Err(format!("target {path} is not a file"));
            }
            let mut head = [0u8; 2];
            File::open(&canonical)
                .and_then(|mut file| file.read_exact(&mut head))
                .map_err(|err| format!("invalid target {path}: {err}"))?;
            if &head != b"MZ" {
                return Err(format!("target {path} is not a Windows PE executable"));
            }
            let canonical_path = canonical
                .to_str()
                .ok_or_else(|| format!("target {path} is not valid UTF-8"))?;
            Ok(Target::Wine {
                path: canonical_path.to_string(),
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
        }
    }
}

fn reject_daemon_tool(path: &Path) -> Result<(), String> {
    let banned = ["netscope", "netscoped", "nft", "ip"];
    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        if banned.contains(&name) {
            return Err(format!("refusing to scope daemon tool {name}"));
        }
    }
    if let Ok(current) = std::env::current_exe() {
        if fs::canonicalize(current).ok().as_deref() == Some(path) {
            return Err("refusing to scope the daemon executable".to_string());
        }
    }
    Ok(())
}

fn duplicate_target(profiles: &BTreeMap<ProfileId, Profile>, target: &Target) -> Option<String> {
    for profile in profiles.values() {
        match (target, &profile.target) {
            (
                Target::Native { dev, ino, .. },
                Target::Native {
                    dev: existing_dev,
                    ino: existing_ino,
                    ..
                },
            ) if dev == existing_dev && ino == existing_ino => {
                return Some(profile.id.clone());
            }
            (
                Target::Wine { dev, ino, .. },
                Target::Wine {
                    dev: existing_dev,
                    ino: existing_ino,
                    ..
                },
            ) if dev == existing_dev && ino == existing_ino => {
                return Some(profile.id.clone());
            }
            (Target::Steam { app_id }, Target::Steam { app_id: existing })
                if app_id == existing =>
            {
                return Some(profile.id.clone());
            }
            _ => {}
        }
    }
    None
}

fn cleanup_all(rt: &Rt, inner: &mut Inner) {
    let profiles: Vec<Profile> = inner.state.profiles.values().cloned().collect();
    for profile in &profiles {
        if let Err(err) = rt.nft.remove(profile) {
            warn!("cleanup profile={} nft error={err}", profile.id);
        }
        if matches!(profile.mode, Mode::Route { .. }) {
            if let Err(err) = ip::remove(profile) {
                warn!("cleanup profile={} ip error={err}", profile.id);
            }
        }
        if let Err(err) = rt.cgroup.remove(&profile.id) {
            warn!("cleanup profile={} cgroup error={err}", profile.id);
        }
    }
    if let Ok(tables) = rt.nft.list_tables() {
        for name in tables {
            if name.starts_with("netscope_filter_") || name.starts_with("netscope_route_") {
                let _ = run("nft", &["delete", "table", "inet", &name], None);
            }
        }
    }
}

fn fanotify_active(rt: &Rt) -> bool {
    rt.fanotify.is_some() && rt.fanotify_ok.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_validation_accepts_prefix_ranges() {
        assert!(parse_cidr("1.1.1.1/32").is_ok());
        assert!(parse_cidr("2001:db8::/32").is_ok());
        assert!(parse_cidr("1.1.1.1/33").is_err());
        assert!(parse_cidr("2001:db8::/129").is_err());
        assert!(parse_cidr("nonsense").is_err());
    }

    #[test]
    fn rfc3339_is_utc_and_fixed_width() {
        let stamp = now_rfc3339();
        assert_eq!(stamp.len(), 20);
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
    }

    #[test]
    fn partial_config_keeps_defaults() {
        let path = std::env::temp_dir().join(format!("netscope-config-{}", std::process::id()));
        std::fs::write(
            &path,
            "[daemon]\nsocket_path = \"/tmp/netscope.sock\"\nstate_path = \"/tmp/netscope.json\"\n",
        )
        .unwrap();
        let cfg = load_config(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(cfg.daemon.socket_path, PathBuf::from("/tmp/netscope.sock"));
        assert_eq!(cfg.daemon.poll_interval_ms, 1000);
        assert_eq!(cfg.daemon.max_profiles, 32);
    }

    #[test]
    fn config_rejects_unknown_and_out_of_range() {
        let path = std::env::temp_dir().join(format!("netscope-bad-config-{}", std::process::id()));
        std::fs::write(&path, "[daemon]\nbogus = 1\n").unwrap();
        assert!(load_config(&path).is_err());
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "[daemon]\nmax_profiles = 0\n").unwrap();
        assert!(load_config(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn oversized_request_is_bounded_and_drained() {
        let mut data = vec![b'a'; MAX_REQUEST_BYTES + 10];
        data.push(b'\n');
        data.extend_from_slice(b"{\"id\":1,\"op\":\"status\"}\n");
        let mut reader = BufReader::new(&data[..]);
        let (line, too_large) = read_line_limited(&mut reader, MAX_REQUEST_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert!(too_large);
        assert!(line.len() <= MAX_REQUEST_BYTES + 1);
        let (line, too_large) = read_line_limited(&mut reader, MAX_REQUEST_BYTES)
            .await
            .unwrap()
            .unwrap();
        assert!(!too_large);
        assert_eq!(line, b"{\"id\":1,\"op\":\"status\"}\n");
    }
}
