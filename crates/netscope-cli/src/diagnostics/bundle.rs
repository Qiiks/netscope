use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use netscope_linux::protocol::{RequestOp, API_VERSION};
use netscope_linux::types::{BundleArgs, Mode, State};
use serde_json::{json, Value};

use crate::client;

use super::doctor;
use super::redact::Redactor;
use super::run_capped;

const SIZE_CAP: u64 = 2 * 1024 * 1024 * 1024;
const TREE_FILE_CAP: u64 = 8 * 1024 * 1024;
const TREE_DEPTH: usize = 8;

#[derive(Clone, Debug)]
pub struct BundleOptions {
    pub include_logs: bool,
    pub include_config: bool,
    pub redact: bool,
    pub acknowledge: bool,
}

impl Default for BundleOptions {
    fn default() -> Self {
        Self {
            include_logs: false,
            include_config: false,
            redact: true,
            acknowledge: false,
        }
    }
}

// Default-options entry point; the CLI's flag-aware path is `support_bundle_with`.
#[allow(dead_code)]
pub fn support_bundle(args: &BundleArgs) -> Result<PathBuf> {
    support_bundle_with(args, &BundleOptions::default())
}

pub fn support_bundle_with(args: &BundleArgs, options: &BundleOptions) -> Result<PathBuf> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("support-bundle requires root: sudo netscope support-bundle");
    }
    if !options.redact && !options.acknowledge {
        bail!("refusing to write an unredacted bundle; add --acknowledge to confirm");
    }
    if options.acknowledge {
        eprintln!(
            "warning: this support bundle may contain sensitive system information; review before uploading"
        );
    }

    let config = client::load_config();
    let stamp = timestamp();
    let paths = BundlePaths {
        config_path: PathBuf::from(client::CONFIG_PATH),
        state_path: config.daemon.state_path.clone(),
        cgroup_root: config.daemon.cgroup_root.clone(),
        socket: client::socket_path(args.socket.as_deref()),
        output: args
            .output
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/tmp/netscope-support-{stamp}.tar.zst"))),
        stamp,
    };
    build_bundle(&paths, options)
}

struct BundlePaths {
    config_path: PathBuf,
    state_path: PathBuf,
    cgroup_root: PathBuf,
    socket: PathBuf,
    output: PathBuf,
    stamp: String,
}

struct Entry {
    name: String,
    bytes: Vec<u8>,
}

struct Builder {
    redact: bool,
    redactor: Redactor,
    entries: Vec<Entry>,
    files: Vec<Value>,
    excluded: Vec<String>,
    errors: Vec<String>,
    total: u64,
}

impl Builder {
    fn new(redact: bool, redactor: Redactor) -> Self {
        Self {
            redact,
            redactor,
            entries: Vec::new(),
            files: Vec::new(),
            excluded: Vec::new(),
            errors: Vec::new(),
            total: 0,
        }
    }

    fn text(&mut self, name: &str, text: impl AsRef<str>) -> Result<()> {
        self.bytes(name, text.as_ref().as_bytes(), true)
    }

    fn manifest(&mut self, name: &str, text: &str) -> Result<()> {
        self.bytes(name, text.as_bytes(), false)
    }

    fn bytes(&mut self, name: &str, bytes: &[u8], redactable: bool) -> Result<()> {
        let (data, redacted) = if self.redact && redactable {
            match self.redactor.redact(bytes) {
                Some(data) => (data, true),
                None => {
                    self.errors
                        .push(format!("{name}: binary content left unredacted"));
                    (bytes.to_vec(), false)
                }
            }
        } else {
            (bytes.to_vec(), false)
        };
        if self.total + len_u64(data.len()) > SIZE_CAP {
            bail!(
                "support bundle exceeds the 2 GiB cap while adding {name} ({} bytes so far)",
                self.total
            );
        }
        self.total += len_u64(data.len());
        self.files.push(json!({
            "path": name,
            "bytes": data.len(),
            "redacted": redacted,
        }));
        self.entries.push(Entry {
            name: name.to_string(),
            bytes: data,
        });
        Ok(())
    }

    fn optional_file(&mut self, member: &str, path: &Path) -> Result<()> {
        match fs::read(path) {
            Ok(bytes) => self.bytes(member, &bytes, true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.excluded.push(format!("{member} (not present)"));
                Ok(())
            }
            Err(err) => {
                self.errors
                    .push(format!("{member}: read {}: {err}", path.display()));
                Ok(())
            }
        }
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn timestamp() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn build_bundle(paths: &BundlePaths, options: &BundleOptions) -> Result<PathBuf> {
    let stamp = &paths.stamp;
    let prefix = format!("netscope-support-{stamp}");

    let (state, state_bytes, state_error) = match fs::read_to_string(&paths.state_path) {
        Ok(text) => match serde_json::from_str::<State>(&text) {
            Ok(state) => (Some(state), Some(text.into_bytes()), None),
            Err(err) => (
                None,
                Some(text.into_bytes()),
                Some(format!(
                    "state.json: parse {}: {err}",
                    paths.state_path.display()
                )),
            ),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (None, None, None),
        Err(err) => (
            None,
            None,
            Some(format!(
                "state.json: read {}: {err}",
                paths.state_path.display()
            )),
        ),
    };
    let state_root = match paths.state_path.parent() {
        Some(parent) => parent.to_path_buf(),
        None => PathBuf::from("."),
    };
    let mut profile_names: Vec<String> = match &state {
        Some(state) => state.profiles.keys().cloned().collect(),
        None => Vec::new(),
    };
    // Profile ids also name directories, so redact them even if state is unreadable.
    if let Ok(entries) = fs::read_dir(state_root.join("profiles")) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                profile_names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let mut builder = Builder::new(options.redact, Redactor::detect(&profile_names));

    collect_version(&mut builder)?;
    collect_system(&mut builder, &paths.cgroup_root)?;
    collect_service(&mut builder)?;
    if options.include_logs {
        collect_logs(&mut builder)?;
    } else {
        builder
            .excluded
            .push("logs.txt (--include-logs not set)".to_string());
    }
    collect_nft(&mut builder)?;
    collect_ip(&mut builder, state.as_ref())?;
    collect_cgroups(&mut builder, &paths.cgroup_root)?;

    if options.include_config {
        builder.optional_file("config.toml", &paths.config_path)?;
    } else {
        builder
            .excluded
            .push("config.toml (--include-config not set)".to_string());
    }
    if let Some(error) = state_error {
        builder.errors.push(error);
    }
    match &state_bytes {
        Some(bytes) => builder.bytes("state.json", bytes, true)?,
        None => builder
            .excluded
            .push("state.json (not present)".to_string()),
    }

    let checks = doctor::run_checks(&paths.socket);
    let ok = checks
        .iter()
        .all(|check| check.status != doctor::Status::Fail);
    builder.text("doctor.txt", doctor::render_text(&checks))?;
    builder.text("doctor.json", doctor::render_json(&checks, ok))?;

    collect_status(&mut builder, &paths.socket)?;

    collect_tree(&mut builder, &state_root.join("profiles"), "profiles")?;
    collect_tree(&mut builder, &state_root.join("late"), "late")?;

    if !builder.errors.is_empty() {
        let errors = format!("{}\n", builder.errors.join("\n"));
        builder.text("errors.txt", errors)?;
    }

    let readme = format!(
        "netscope support bundle\n\
         generated: {stamp}\n\
         generated by: netscope {}\n\n\
         Review this archive before uploading it. It is never uploaded automatically.\n\
         Redaction is best effort: some paths, interface names, and most IP addresses remain\n\
         because they are needed to diagnose routing and attachment problems. Profile names are\n\
         replaced with placeholders.\n\
         errors.txt lists collection steps that failed or produced warnings.\n",
        env!("CARGO_PKG_VERSION")
    );
    builder.text("README.txt", readme)?;

    let mut excluded = vec![
        "/proc contents (never collected)".to_string(),
        "shell history".to_string(),
        "arbitrary home-directory files".to_string(),
        "/etc/passwd and /etc/shadow".to_string(),
        "SSH and other private keys".to_string(),
        "environment dumps".to_string(),
        "packet captures".to_string(),
        "browser data".to_string(),
        "core dumps".to_string(),
        "complete nftables ruleset".to_string(),
        "complete routing table".to_string(),
    ];
    excluded.extend(builder.excluded.clone());
    let redactor = &builder.redactor;
    let excluded: Vec<String> = excluded
        .into_iter()
        .map(|entry| redactor.redact_text(&entry))
        .collect();
    let manifest = json!({
        "generated_by": format!("netscope {}", env!("CARGO_PKG_VERSION")),
        "generated_at": stamp,
        "files": builder.files.clone(),
        "redaction": {
            "enabled": options.redact,
            "labels": {
                "home": "<home>",
                "user": "<user>",
                "host": "<host>",
                "profile": "<profile-N>",
                "secret": "[REDACTED]",
                "mac": "[MAC]",
                "link_local_ipv6": "<link-local>",
                "token": "<redacted>",
            },
            "scope": "all collected text files; binary files are left unchanged with a warning",
            "note": "best effort; review before uploading",
        },
        "excluded": excluded,
    });
    builder.manifest(
        "manifest.json",
        &serde_json::to_string_pretty(&manifest).context("encode manifest")?,
    )?;

    write_archive(&builder.entries, &prefix, &paths.output)?;
    Ok(paths.output.clone())
}

fn collect_version(builder: &mut Builder) -> Result<()> {
    let daemon = run_capped("netscoped", &["--version"])
        .ok()
        .filter(|output| output.status == Some(0))
        .map(|output| {
            output
                .stdout
                .lines()
                .chain(output.stderr.lines())
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        })
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown (netscoped --version unavailable)".to_string());
    builder.text(
        "version.txt",
        format!(
            "netscope {}\n\
             {daemon}\n\
             api_version {API_VERSION}\n\
             architecture {}\n",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH
        ),
    )
}

fn collect_system(builder: &mut Builder, cgroup_root: &Path) -> Result<()> {
    let kernel = doctor::kernel_release().unwrap_or_else(|| "unknown".to_string());
    let distro = fs::read_to_string("/etc/os-release")
        .ok()
        .map(|text| {
            text.lines()
                .filter(|line| {
                    line.starts_with("PRETTY_NAME=")
                        || line.starts_with("ID=")
                        || line.starts_with("VERSION_ID=")
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|| "unknown".to_string());
    let cgroup2 = Path::new("/sys/fs/cgroup/cgroup.controllers").is_file();
    let nft = tool_version("nft", &["--version"]);
    let ip = tool_version("ip", &["-V"]);
    builder.text(
        "system.txt",
        format!(
            "kernel: {kernel}\n\
             architecture: {}\n\
             cgroup v2: {}\n\
             cgroup root: {}\n\
             {distro}\n\
             nft: {nft}\n\
             ip: {ip}\n",
            std::env::consts::ARCH,
            if cgroup2 { "yes" } else { "no" },
            cgroup_root.display()
        ),
    )
}

fn tool_version(program: &str, args: &[&str]) -> String {
    run_capped(program, args)
        .ok()
        .filter(|output| output.status == Some(0))
        .and_then(|output| {
            output
                .stdout
                .lines()
                .chain(output.stderr.lines())
                .find(|line| !line.trim().is_empty())
                .map(|line| line.trim().to_string())
        })
        .unwrap_or_else(|| "unavailable".to_string())
}

fn append_command(
    output: &mut String,
    title: &str,
    program: &str,
    args: &[&str],
    errors: &mut Vec<String>,
) {
    output.push_str(&format!("$ {title}\n"));
    match run_capped(program, args) {
        Ok(result) => {
            output.push_str(&result.stdout);
            if !result.stdout.ends_with('\n') {
                output.push('\n');
            }
            if !result.stderr.is_empty() {
                output.push_str(&result.stderr);
                if !result.stderr.ends_with('\n') {
                    output.push('\n');
                }
            }
            if result.timed_out {
                output.push_str("[timed out after 10s]\n");
            }
            if result.truncated {
                output.push_str("[output truncated at 256 KiB]\n");
            }
            if result.status != Some(0) {
                output.push_str(&format!(
                    "[exit {}]\n",
                    result
                        .status
                        .map_or_else(|| "timeout".to_string(), |code| code.to_string())
                ));
            }
        }
        Err(err) => errors.push(format!("{title}: {err}")),
    }
    output.push('\n');
}

fn collect_service(builder: &mut Builder) -> Result<()> {
    let mut text = String::new();
    append_command(
        &mut text,
        "systemctl status netscoped --no-pager",
        "systemctl",
        &["status", "netscoped", "--no-pager"],
        &mut builder.errors,
    );
    builder.text("service.txt", text)
}

fn collect_logs(builder: &mut Builder) -> Result<()> {
    let mut text = String::new();
    append_command(
        &mut text,
        "journalctl -u netscoped -n 200 --no-pager",
        "journalctl",
        &["-u", "netscoped", "-n", "200", "--no-pager"],
        &mut builder.errors,
    );
    builder.text("logs.txt", text)
}

fn collect_nft(builder: &mut Builder) -> Result<()> {
    let mut text = String::new();
    let tables = match run_capped("nft", &["-j", "list", "tables"]) {
        Ok(output) if output.status == Some(0) => parse_table_names(&output.stdout)
            .into_iter()
            .filter(|name| name.starts_with("netscope_"))
            .collect::<Vec<_>>(),
        Ok(output) => {
            builder.errors.push(format!(
                "nft list tables: exit {}: {}",
                output
                    .status
                    .map_or_else(|| "timeout".to_string(), |code| code.to_string()),
                output.stderr.trim()
            ));
            Vec::new()
        }
        Err(err) => {
            builder.errors.push(format!("nft list tables: {err}"));
            Vec::new()
        }
    };
    if tables.is_empty() {
        text.push_str("no netscope_* nftables tables\n");
    }
    for table in tables {
        append_command(
            &mut text,
            &format!("nft list table inet {table}"),
            "nft",
            &["list", "table", "inet", &table],
            &mut builder.errors,
        );
    }
    builder.text("nft.txt", text)
}

fn parse_table_names(text: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    value
        .get("nftables")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("table"))
                .filter_map(|table| table.get("name"))
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn collect_ip(builder: &mut Builder, state: Option<&State>) -> Result<()> {
    let mut text = String::new();
    append_command(
        &mut text,
        "ip -4 rule show",
        "ip",
        &["-4", "rule", "show"],
        &mut builder.errors,
    );
    append_command(
        &mut text,
        "ip -6 rule show",
        "ip",
        &["-6", "rule", "show"],
        &mut builder.errors,
    );

    let mut tables = BTreeSet::new();
    if let Some(state) = state {
        for profile in state.profiles.values() {
            if let Mode::Route { allow_ipv6, .. } = &profile.mode {
                tables.insert((profile.table, *allow_ipv6));
            }
        }
    }
    for (table, allow_ipv6) in tables {
        append_command(
            &mut text,
            &format!("ip -4 route show table {table}"),
            "ip",
            &["-4", "route", "show", "table", &table.to_string()],
            &mut builder.errors,
        );
        if allow_ipv6 {
            append_command(
                &mut text,
                &format!("ip -6 route show table {table}"),
                "ip",
                &["-6", "route", "show", "table", &table.to_string()],
                &mut builder.errors,
            );
        }
    }
    builder.text("ip.txt", text)
}

fn collect_cgroups(builder: &mut Builder, cgroup_root: &Path) -> Result<()> {
    let mut text = format!("cgroup root: {}\n", cgroup_root.display());
    for (label, path) in [
        ("root", cgroup_root.join("cgroup.procs")),
        ("controllers", cgroup_root.join("cgroup.controllers")),
    ] {
        if let Ok(value) = fs::read_to_string(&path) {
            text.push_str(&format!("\n{label} {}:\n{value}", path.display()));
        }
    }
    match fs::read_dir(cgroup_root) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let procs = path.join("cgroup.procs");
                match fs::read_to_string(&procs) {
                    Ok(value) => {
                        text.push_str(&format!("\n{}:\n{value}", path.display()));
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => builder.errors.push(format!("{}: {err}", procs.display())),
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            builder
                .excluded
                .push(format!("cgroups.txt ({} missing)", cgroup_root.display()));
            return Ok(());
        }
        Err(err) => {
            builder
                .errors
                .push(format!("read {}: {err}", cgroup_root.display()));
        }
    }
    builder.text("cgroups.txt", text)
}

fn collect_status(builder: &mut Builder, socket: &Path) -> Result<()> {
    match client::send(socket, RequestOp::Status) {
        Ok(Some(data)) => {
            if let Ok(text) = serde_json::to_string_pretty(&data) {
                builder.text("status.json", text)?;
            }
        }
        Ok(None) => builder
            .errors
            .push("status.json: daemon returned no status data".to_string()),
        Err(err) => builder
            .errors
            .push(format!("status.json: {}", err.message())),
    }
    match client::send(socket, RequestOp::List) {
        Ok(Some(data)) => {
            if let Ok(text) = serde_json::to_string_pretty(&data) {
                builder.text("list.json", text)?;
            }
        }
        Ok(None) => builder
            .errors
            .push("list.json: daemon returned no list data".to_string()),
        Err(err) => builder.errors.push(format!("list.json: {}", err.message())),
    }
    Ok(())
}

fn collect_tree(builder: &mut Builder, root: &Path, member_prefix: &str) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > TREE_DEPTH {
            builder
                .excluded
                .push(format!("{member_prefix}/{} (depth limit)", dir.display()));
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                builder
                    .errors
                    .push(format!("read {}: {err}", dir.display()));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                builder
                    .excluded
                    .push(format!("{member_prefix}/{} (symlink)", path.display()));
                continue;
            }
            if file_type.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let member = format!("{member_prefix}/{relative}");
            let size = entry.metadata().map_or(0, |meta| meta.len());
            if size > TREE_FILE_CAP {
                builder
                    .excluded
                    .push(format!("{member} (larger than 8 MiB)"));
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    builder.errors.push(format!("{member}: {err}"));
                    continue;
                }
            };
            builder.bytes(&member, &bytes, true)?;
        }
    }
    Ok(())
}

fn write_archive(entries: &[Entry], prefix: &str, output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temp = output.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(0)
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("create {}", temp.display()))?;

    let result = (|| -> Result<()> {
        let encoder = zstd::Encoder::new(file, 3).context("start zstd")?;
        let mut tar = tar::Builder::new(encoder);
        for entry in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(len_u64(entry.bytes.len()));
            header.set_mode(0o600);
            header.set_mtime(0);
            header.set_cksum();
            let path = format!("{prefix}/{}", entry.name);
            tar.append_data(&mut header, &path, entry.bytes.as_slice())
                .with_context(|| format!("archive {path}"))?;
        }
        let encoder = tar.into_inner().context("finish tar")?;
        let file = encoder.finish().context("finish zstd")?;
        file.sync_all().context("sync bundle")?;
        Ok(())
    })();

    if let Err(err) = result {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    fs::rename(&temp, output).with_context(|| format!("replace {}", output.display()))?;
    let _ = fs::set_permissions(output, fs::Permissions::from_mode(0o600));
    chown_sudo(output);
    Ok(())
}

fn chown_sudo(path: &Path) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return;
    };
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    unsafe {
        libc::chown(path.as_ptr(), uid, gid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn temp_dir() -> PathBuf {
        let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "netscope-bundle-test-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn read_archive(path: &Path) -> Vec<(String, Vec<u8>)> {
        let file = fs::File::open(path).expect("open archive");
        let decoder = zstd::Decoder::new(file).expect("zstd decoder");
        let mut archive = tar::Archive::new(decoder);
        let mut entries = Vec::new();
        for entry in archive.entries().expect("archive entries") {
            let mut entry = entry.expect("entry");
            let name = entry.path().expect("path").to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).expect("read entry");
            entries.push((name, bytes));
        }
        entries
    }

    #[test]
    fn redacted_config_round_trips_and_keeps_routing_flags() {
        let redactor = Redactor {
            homes: vec!["/home/alice".to_string()],
            users: vec!["alice".to_string()],
            host: Some("workstation".to_string()),
            profiles: vec![("game".to_string(), "<profile-1>".to_string())],
        };
        let config = "[daemon]\n\
                      socket_path = \"/home/alice/.netscope/control.sock\"\n\
                      state_path = \"/home/alice/.netscope/state.json\"\n\
                      cgroup_root = \"/sys/fs/cgroup/netscope\"\n\
                      poll_interval_ms = 1000\n\
                      refresh_interval_secs = 5\n\
                      max_profiles = 32\n\
                      log_level = \"info\"\n\
                      password = \"hunter2\"\n";
        let redacted = redactor.redact_text(config);
        let value: toml::Value = redacted.parse().expect("redacted config still parses");
        assert_eq!(
            value["daemon"]["cgroup_root"].as_str(),
            Some("/sys/fs/cgroup/netscope")
        );
        assert_eq!(value["daemon"]["max_profiles"].as_integer(), Some(32));
        assert!(
            redacted.contains("<home>/.netscope/control.sock"),
            "{redacted}"
        );
        assert!(!redacted.contains("hunter2"), "{redacted}");
    }

    #[test]
    fn bundle_includes_and_excludes_expected_members() {
        let dir = temp_dir();
        let config = dir.join("config.toml");
        let state = dir.join("state.json");
        let profiles = dir.join("profiles").join("game");
        fs::create_dir_all(&profiles).expect("profiles dir");
        fs::write(
            &config,
            "[daemon]\nsocket_path = \"/tmp/netscope-test.sock\"\nsecret = \"hunter2\"\n",
        )
        .expect("config");
        fs::write(&state, "{\"version\":1,\"profiles\":{}}").expect("state");
        fs::write(profiles.join("note.txt"), "profile note for alice").expect("profile file");
        let output = dir.join("bundle.tar.zst");
        let paths = BundlePaths {
            config_path: config,
            state_path: state,
            cgroup_root: dir.join("cgroup"),
            socket: dir.join("control.sock"),
            output: output.clone(),
            stamp: "20261030T221500Z".to_string(),
        };
        let options = BundleOptions {
            include_logs: false,
            include_config: true,
            redact: true,
            acknowledge: false,
        };
        build_bundle(&paths, &options).expect("bundle builds");
        let entries = read_archive(&output);
        let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
        let prefix = names
            .first()
            .and_then(|name| name.split('/').next())
            .expect("archive prefix");
        assert!(prefix.starts_with("netscope-support-"), "{names:?}");
        for expected in [
            "README.txt",
            "manifest.json",
            "config.toml",
            "state.json",
            "doctor.txt",
            "doctor.json",
            "system.txt",
            "profiles/game/note.txt",
        ] {
            assert!(
                names.contains(&format!("{prefix}/{expected}").as_str()),
                "missing {expected}: {names:?}"
            );
        }
        assert!(
            !names.iter().any(|name| name.ends_with("/logs.txt")),
            "{names:?}"
        );
        let config_entry = entries
            .iter()
            .find(|(name, _)| name.ends_with("/config.toml"))
            .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
            .expect("config entry");
        assert!(!config_entry.contains("hunter2"), "{config_entry}");
        let manifest: Value = serde_json::from_slice(
            &entries
                .iter()
                .find(|(name, _)| name.ends_with("/manifest.json"))
                .map(|(_, bytes)| bytes.clone())
                .expect("manifest"),
        )
        .expect("manifest json");
        assert_eq!(manifest["redaction"]["enabled"].as_bool(), Some(true));
        assert!(manifest["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()));
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn table_names_are_filtered_from_nft_json() {
        let names = parse_table_names(
            r#"{"nftables":[{"metainfo":{}},{"table":{"name":"netscope_filter_game"}},{"table":{"name":"filter"}}]}"#,
        );
        assert_eq!(names, vec!["netscope_filter_game", "filter"]);
    }
}
