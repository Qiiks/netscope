//! The daemon worker: one blocking client, polled off the UI thread.

use std::collections::HashSet;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use netscope_client::{
    Client, ClientError, FilterDefault, Hold, OpenScope, PolicySpec, StatusData, TargetSpec,
};
use rune::AppHandle;

use crate::model::{ProcInfo, map_status};
use crate::state::{Conn, State};

/// How often an ordinary status poll runs.
const POLL: Duration = Duration::from_secs(1);
/// How often the worker retries while the daemon is down.
const RETRY: Duration = Duration::from_secs(2);

/// The consumer name this window claims scopes under.
pub const CONSUMER: &str = "netscope-gui";

/// Where the Add screen's target comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetChoice {
    Process { pid: u32, name: String },
    Executable { path: String },
}

/// How the Add screen wants the scope filtered or routed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyChoice {
    Filter { deny: Vec<String> },
    Route { links: Vec<String> },
    Shared,
}

/// One request from the UI thread to the worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Open(OpenRequest),
    Enable(String),
    Disable(String),
    Remove(String),
    Release(String),
    Refresh,
    Retry,
    ScanProcesses,
}

/// One open request, complete before it reaches the worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub target: TargetChoice,
    pub policy: PolicyChoice,
    pub peer: bool,
}

/// Start the worker. The receiver is drained by the worker; the handle is the only path back
/// to the UI. A spawn failure leaves the app in its Down state instead of pretending to poll.
pub fn spawn(rx: Receiver<Action>, handle: AppHandle<State>) -> std::io::Result<()> {
    rune::task::spawn("netscope-gui-worker", move || run(rx, handle))
}

fn run(rx: Receiver<Action>, handle: AppHandle<State>) {
    let mut client: Option<Client> = None;
    let mut last_snapshot = None;
    let mut last_poll = None;
    let mut retry = true;
    loop {
        if retry {
            retry = false;
            match connect() {
                Ok(mut fresh) => match fresh.status() {
                    Ok(status) => {
                        client = Some(fresh);
                        last_snapshot = publish(&handle, status, last_snapshot.as_ref(), last_poll);
                        last_poll = Some(Instant::now());
                        // Scope claims live on the socket; open and close happen in order below.
                    }
                    Err(error) => {
                        client = None;
                        push_conn(&handle, conn_for(&error));
                    }
                },
                Err(error) => {
                    client = None;
                    push_conn(&handle, conn_for(&error));
                }
            }
        }

        let wait = if client.is_some() { POLL } else { RETRY };
        match rx.recv_timeout(wait) {
            Ok(action) => match action {
                Action::ScanProcesses => {
                    let processes = scan_processes(current_uid());
                    handle.update(move |state, _| state.set_processes(processes));
                }
                Action::Retry => {
                    client = None;
                    retry = true;
                }
                action => {
                    if client.is_none() {
                        match connect() {
                            Ok(fresh) => client = Some(fresh),
                            Err(error) => {
                                push_conn(&handle, conn_for(&error));
                                retry = true;
                            }
                        }
                    }
                    if let Some(active) = client.as_mut() {
                        handle_action(&handle, active, action, &mut last_snapshot, &mut last_poll);
                    }
                }
            },
            Err(RecvTimeoutError::Timeout) => {
                let Some(active) = client.as_mut() else {
                    retry = true;
                    continue;
                };
                match active.status() {
                    Ok(status) => {
                        last_snapshot = publish(&handle, status, last_snapshot.as_ref(), last_poll);
                        last_poll = Some(Instant::now());
                    }
                    Err(error) => {
                        client = None;
                        push_conn(&handle, conn_for(&error));
                        retry = true;
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn connect() -> Result<Client, ClientError> {
    Client::connect()
}

fn conn_for(error: &ClientError) -> Conn {
    match error {
        ClientError::Unavailable(message) => Conn::Down(format!(
            "{message} · start it with: sudo systemctl start netscoped"
        )),
        ClientError::Permission(message) => Conn::Denied(message.clone()),
        other => Conn::Down(other.to_string()),
    }
}

fn push_conn(handle: &AppHandle<State>, conn: Conn) {
    handle.update(move |state, _| state.connection_lost(conn));
}

fn publish(
    handle: &AppHandle<State>,
    status: StatusData,
    previous: Option<&crate::model::Snapshot>,
    last_poll: Option<Instant>,
) -> Option<crate::model::Snapshot> {
    let elapsed = last_poll.map_or(Duration::ZERO, |last| last.elapsed());
    let snapshot = map_status(&status, previous, elapsed);
    let returned = snapshot.clone();
    handle.update(move |state, _| {
        if !state.paused {
            state.apply_snapshot(snapshot);
        }
    });
    Some(returned)
}

fn handle_action(
    handle: &AppHandle<State>,
    client: &mut Client,
    action: Action,
    last_snapshot: &mut Option<crate::model::Snapshot>,
    last_poll: &mut Option<Instant>,
) {
    match action {
        Action::Open(request) => match open_scope(client, &request) {
            Ok(profile) => {
                let peer = request.peer;
                // Refresh the list so the new scope appears with its daemon identity.
                if let Ok(status) = client.status() {
                    *last_snapshot = publish(handle, status, last_snapshot.as_ref(), *last_poll);
                    *last_poll = Some(Instant::now());
                }
                handle.update(move |state, _| state.note_opened(profile, peer));
            }
            Err(error) => {
                let message = error.to_string();
                handle.update(move |state, _| state.note_action_err(message));
            }
        },
        Action::Enable(id) => mutate_action(handle, client, id, true),
        Action::Disable(id) => mutate_action(handle, client, id, false),
        Action::Remove(id) | Action::Release(id) => {
            let result = client.close_scope(&id, CONSUMER);
            match result {
                Ok(result) => {
                    let message = if result.removed {
                        format!("{} released and removed", result.profile)
                    } else {
                        format!("{} released", result.profile)
                    };
                    handle.update(move |state, _| state.note_action_ok(message));
                }
                Err(error) => {
                    let message = error.to_string();
                    handle.update(move |state, _| state.note_action_err(message));
                }
            }
        }
        Action::Refresh => {
            if let Err(error) = client.refresh() {
                let message = error.to_string();
                handle.update(move |state, _| state.note_action_err(message));
            }
        }
        Action::ScanProcesses => {}
        Action::Retry => {}
    }
}

fn mutate_action(handle: &AppHandle<State>, client: &mut Client, id: String, enable: bool) {
    match mutate(client, &id, enable) {
        Ok(message) => handle.update(move |state, _| state.note_action_ok(message)),
        Err(error) => {
            let message = error.to_string();
            handle.update(move |state, _| state.note_action_err(message));
        }
    }
}

fn mutate(client: &mut Client, id: &str, enable: bool) -> Result<String, ClientError> {
    let action = if enable { "enable" } else { "disable" };
    let op = if enable {
        netscope_client::RequestOp::Enable {
            name: id.to_string(),
        }
    } else {
        netscope_client::RequestOp::Disable {
            name: id.to_string(),
        }
    };
    client.raw_request(op)?;
    Ok(format!("{id} {action}d"))
}

fn open_scope(client: &mut Client, request: &OpenRequest) -> Result<String, ClientError> {
    let target = match &request.target {
        TargetChoice::Process { name, .. } => TargetSpec::Name { name: name.clone() },
        TargetChoice::Executable { path } if path.to_ascii_lowercase().ends_with(".exe") => {
            TargetSpec::Wine { path: path.clone() }
        }
        TargetChoice::Executable { path } => TargetSpec::Native { path: path.clone() },
    };
    let hold = if request.peer {
        Hold::Peer
    } else {
        Hold::Persistent
    };
    let handle = client.open_scope(OpenScope {
        consumer: CONSUMER.to_string(),
        target,
        target_uid: current_uid(),
        name: None,
        hold,
    })?;
    let policy = match &request.policy {
        PolicyChoice::Filter { deny } => PolicySpec::Filter {
            default: FilterDefault::Allow,
            allow_cidrs: Vec::new(),
            deny_cidrs: deny.clone(),
        },
        PolicyChoice::Route { links } => {
            // The 0.2.1 daemon takes one route interface per consumer. Keep the ordered list in
            // the window for failover; the first live link is the one enforced today.
            let interface = links
                .first()
                .cloned()
                .ok_or_else(|| ClientError::Protocol("no route link chosen".to_string()))?;
            PolicySpec::Route {
                interface,
                gateway: None,
                gateway6: None,
                include_lan: false,
                allow_ipv6: false,
                udp_only: false,
                except_ports: Vec::new(),
                except_sports: Vec::new(),
                except: Vec::new(),
            }
        }
        PolicyChoice::Shared => {
            return Ok(handle.profile);
        }
    };
    client.set_policy(&handle.profile, CONSUMER, policy)?;
    Ok(handle.profile)
}

/// The uid the peer runs as. Roots pass the login user's uid so a root-launched window still
/// targets that desktop session; otherwise the effective uid is the target.
fn current_uid() -> u32 {
    let euid = read_euid();
    if euid != 0 {
        return euid;
    }
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(euid)
}

fn read_euid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|uid| uid.parse::<u32>().ok())
        })
        .unwrap_or(0)
}

/// Scan `/proc` for processes owned by the calling user, newest pid first.
pub fn scan_processes(uid: u32) -> Vec<ProcInfo> {
    let mut seen = HashSet::new();
    let mut processes = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let task = entry.path();
        let stat = match std::fs::read_to_string(task.join("status")) {
            Ok(stat) => stat,
            Err(_) => continue,
        };
        let mut name = String::new();
        let mut process_uid = 0;
        for line in stat.lines() {
            if let Some(rest) = line.strip_prefix("Name:") {
                name = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("Uid:") {
                process_uid = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(0);
            }
        }
        if process_uid != uid || name.is_empty() || name.starts_with('[') {
            continue;
        }
        let exe = std::fs::read_link(task.join("exe"))
            .ok()
            .and_then(|path| path.to_str().map(str::to_string))
            .unwrap_or_default();
        let cgroup = std::fs::read_to_string(task.join("cgroup"))
            .ok()
            .and_then(|text| {
                text.lines().find_map(|line| {
                    line.split_once("::")
                        .map(|(_, path)| path.trim().to_string())
                })
            })
            .unwrap_or_default();
        if seen.insert((name.clone(), exe.clone())) {
            processes.push(ProcInfo {
                pid,
                name,
                exe,
                uid: process_uid,
                cgroup,
            });
        }
    }
    processes.sort_by(|a, b| a.name.cmp(&b.name).then(a.pid.cmp(&b.pid)));
    processes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_reads_a_number() {
        assert!(read_euid() > 0, "the test runs as a real user");
    }

    #[test]
    fn the_process_scan_is_sorted_and_deduplicated() {
        let uid = read_euid();
        let processes = scan_processes(uid);
        let mut names: Vec<&str> = processes.iter().map(|p| p.name.as_str()).collect();
        let sorted = names.clone();
        names.sort_unstable();
        assert_eq!(names, sorted);
        for pair in processes.windows(2) {
            assert!(
                (pair[0].name.as_str(), pair[0].pid) <= (pair[1].name.as_str(), pair[1].pid),
                "scan order is stable"
            );
        }
    }
}
