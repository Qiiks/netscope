//! Application state and the actions the screens can take.

use std::sync::mpsc::Sender;

use rune::TextEdit;
use rune::tray::Tray;

use crate::model::{
    Activity, Link, ProcInfo, Profile, Snapshot, Stats, Tone, clock_now, demo_activity,
    demo_processes, demo_snapshot, demo_spark, fmt_rate, now_unix,
};
use crate::worker::{Action, OpenRequest, PolicyChoice, TargetChoice};

/// The screens reachable from the rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Apps,
    Add,
    Doctor,
}

/// The scene names accepted by `--scene`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scene {
    Overview,
    Scopes,
    Add,
    Doctor,
    Empty,
    Down,
    Denied,
    Narrow,
}

/// Where the application is in its connection to `netscoped`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Conn {
    Connecting,
    Live,
    Down(String),
    Denied(String),
}

/// A transient line under the banner, usually the result of the last action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub message: String,
    pub ok: bool,
}

/// One denial destination the Add screen offers.
pub const FILTER_CIDRS: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16"];

/// Where the Add screen takes its target from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddSource {
    Process,
    Executable,
}

/// The application state. Screen data lives in `snapshot`; live mode never fills it except
/// from a daemon reply.
pub struct State {
    pub screen: Screen,
    pub conn: Conn,
    pub snapshot: Option<Snapshot>,
    pub stale: bool,
    pub paused: bool,
    pub demo: bool,
    pub activity: Vec<Activity>,
    pub history_tx: Vec<f32>,
    pub history_rx: Vec<f32>,
    pub rate_history: bool,
    pub notice: Option<Notice>,
    pub selected_profile: usize,
    pub processes: Vec<ProcInfo>,
    pub scanning: bool,
    pub selected_proc: usize,
    pub add_source: AddSource,
    pub add_mode: crate::model::Mode,
    pub add_deny: [bool; 3],
    pub add_route: Vec<String>,
    pub add_exe: TextEdit,
    pub add_link: TextEdit,
    pub release_on_close: bool,
    pub opening: bool,
    pub add_error: Option<String>,
    pub pending_remove: Option<String>,
    pub peer_owned: Vec<String>,
    pub tx: Option<Sender<Action>>,
    pub tray: Option<Tray>,
}

impl State {
    /// A live state: connecting, no snapshot, counters unavailable.
    pub fn live(tx: Option<Sender<Action>>, tray: Option<Tray>) -> State {
        State {
            screen: Screen::Overview,
            conn: Conn::Connecting,
            snapshot: None,
            stale: false,
            paused: false,
            demo: false,
            activity: vec![Activity::now("connecting to netscoped", Tone::Muted)],
            history_tx: vec![0.0; 40],
            history_rx: vec![0.0; 40],
            rate_history: false,
            notice: None,
            selected_profile: 0,
            processes: Vec::new(),
            scanning: false,
            selected_proc: 0,
            add_source: AddSource::Process,
            add_mode: crate::model::Mode::Route,
            add_deny: [true, false, false],
            add_route: Vec::new(),
            add_exe: TextEdit::new(""),
            add_link: TextEdit::new(""),
            release_on_close: true,
            opening: false,
            add_error: None,
            pending_remove: None,
            peer_owned: Vec::new(),
            tx,
            tray,
        }
    }

    /// The demonstration state used by `--demo` and every headless scene.
    pub fn demo(tray: Option<Tray>) -> State {
        let snapshot = demo_snapshot();
        let route: Vec<String> = snapshot
            .links
            .iter()
            .filter(|link| link.up)
            .map(|link| link.interface.clone())
            .collect();
        let peer_owned = snapshot
            .profiles
            .iter()
            .take(2)
            .map(|profile| profile.id.clone())
            .collect();
        State {
            screen: Screen::Overview,
            conn: Conn::Live,
            snapshot: Some(snapshot),
            stale: false,
            paused: false,
            demo: true,
            activity: demo_activity(),
            history_tx: demo_spark(),
            history_rx: demo_spark(),
            rate_history: true,
            notice: None,
            selected_profile: 0,
            processes: demo_processes(),
            scanning: false,
            selected_proc: 0,
            add_source: AddSource::Process,
            add_mode: crate::model::Mode::Route,
            add_deny: [true, false, false],
            add_route: route,
            add_exe: TextEdit::new(""),
            add_link: TextEdit::new(""),
            release_on_close: true,
            opening: false,
            add_error: None,
            pending_remove: None,
            peer_owned,
            tx: None,
            tray,
        }
    }

    /// Reset to the demonstration state and apply one scene. The tray, if any, survives.
    pub fn reset_demo(&mut self, scene: Scene) {
        let tray = self.tray.take();
        let mut fresh = State::demo(tray);
        match scene {
            Scene::Overview => {}
            Scene::Narrow => {}
            Scene::Scopes => fresh.screen = Screen::Apps,
            Scene::Add => fresh.screen = Screen::Add,
            Scene::Doctor => fresh.screen = Screen::Doctor,
            Scene::Empty => {
                fresh.screen = Screen::Apps;
                if let Some(snapshot) = fresh.snapshot.as_mut() {
                    snapshot.profiles.clear();
                    snapshot.links.clear();
                }
                fresh.selected_profile = 0;
                fresh.peer_owned.clear();
                fresh.rate_history = false;
                fresh.history_tx = vec![0.0; 40];
                fresh.history_rx = vec![0.0; 40];
            }
            Scene::Down => {
                fresh.screen = Screen::Overview;
                fresh.conn = Conn::Down(
                    "daemon not running; start with: sudo systemctl start netscoped".to_string(),
                );
                fresh.stale = true;
                fresh.activity.insert(
                    0,
                    Activity::now("daemon unreachable · retrying every 2 s", Tone::Bad),
                );
            }
            Scene::Denied => {
                fresh.screen = Screen::Overview;
                fresh.conn = Conn::Denied(
                    "permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER"
                        .to_string(),
                );
                fresh.snapshot = None;
                fresh.stale = false;
                fresh.rate_history = false;
                fresh.history_tx = vec![0.0; 40];
                fresh.history_rx = vec![0.0; 40];
                fresh.activity.insert(
                    0,
                    Activity::now("permission denied · group hint shown", Tone::Bad),
                );
            }
        }
        *self = fresh;
    }

    pub fn apply_snapshot(&mut self, snapshot: Snapshot) {
        let version = snapshot.daemon_version.clone();
        let generation = snapshot.generation();
        let count = snapshot.profiles.len();
        let first_live = self.conn != Conn::Live;
        let generation_changed = self
            .snapshot
            .as_ref()
            .map(Snapshot::generation)
            .is_some_and(|previous| previous != generation);
        self.snapshot = Some(snapshot);
        self.conn = Conn::Live;
        self.stale = false;
        self.opening = false;
        self.clamp_selection();
        self.push_history();
        if first_live {
            self.push_activity(format!("connected · netscoped {version}"), Tone::Good);
        } else if generation_changed {
            self.push_activity(
                format!("generation {generation} · {count} profiles"),
                Tone::Muted,
            );
        }
        self.refresh_tray();
    }

    pub fn connection_lost(&mut self, conn: Conn) {
        let same = matches!(
            (&self.conn, &conn),
            (Conn::Connecting, Conn::Connecting)
                | (Conn::Live, Conn::Live)
                | (Conn::Down(_), Conn::Down(_))
                | (Conn::Denied(_), Conn::Denied(_))
        );
        let denied = matches!(&conn, Conn::Denied(_));
        self.conn = conn;
        if denied {
            self.snapshot = None;
            self.peer_owned.clear();
        }
        self.stale = self.snapshot.is_some() && matches!(self.conn, Conn::Down(_));
        self.opening = false;
        if !same {
            let (message, tone) = match &self.conn {
                Conn::Connecting => ("connecting to netscoped", Tone::Muted),
                Conn::Down(_) => ("daemon unreachable · retrying every 2 s", Tone::Bad),
                Conn::Denied(_) => ("permission denied · group hint shown", Tone::Bad),
                Conn::Live => ("connected", Tone::Good),
            };
            self.push_activity(message, tone);
        }
        self.refresh_tray();
    }

    fn push_activity(&mut self, message: impl Into<String>, tone: Tone) {
        self.activity.insert(
            0,
            Activity {
                time: clock_now(),
                message: message.into(),
                tone,
            },
        );
        self.activity.truncate(12);
    }

    fn push_history(&mut self) {
        let (Some(rx), Some(tx)) = (self.total_rx(), self.total_tx()) else {
            return;
        };
        if self.history_tx.len() >= 40 {
            self.history_tx.remove(0);
            self.history_rx.remove(0);
        }
        self.history_tx.push(tx as f32);
        self.history_rx.push(rx as f32);
        self.rate_history = true;
    }

    /// The profile the Apps screen is showing.
    pub fn selected(&self) -> Option<&Profile> {
        let snapshot = self.snapshot.as_ref()?;
        if snapshot.profiles.is_empty() {
            return None;
        }
        snapshot
            .profiles
            .get(self.selected_profile.min(snapshot.profiles.len() - 1))
    }

    pub fn selected_id(&self) -> Option<String> {
        self.selected().map(|profile| profile.id.clone())
    }

    fn clamp_selection(&mut self) {
        let len = self.snapshot.as_ref().map_or(0, |s| s.profiles.len());
        self.selected_profile = if len == 0 {
            0
        } else {
            self.selected_profile.min(len - 1)
        };
    }

    pub fn select_profile(&mut self, index: usize) {
        self.selected_profile = index;
        self.clamp_selection();
        self.pending_remove = None;
    }

    /// Switch screens from the rail or a button. Add prepares its scan on entry.
    pub fn goto(&mut self, screen: Screen) {
        if screen == Screen::Add {
            self.begin_add();
        } else {
            self.screen = screen;
            self.pending_remove = None;
        }
    }

    pub fn total_tx(&self) -> Option<u64> {
        self.sum_enabled(|stats| stats.tx_bps)
    }

    pub fn total_rx(&self) -> Option<u64> {
        self.sum_enabled(|stats| stats.rx_bps)
    }

    pub fn total_pps(&self) -> Option<u64> {
        self.sum_enabled(|stats| Some(stats.packet_rate()))
    }

    pub fn total_dropped(&self) -> Option<u64> {
        self.sum_enabled(|stats| Some(stats.dropped_packets))
    }

    fn sum_enabled(&self, pick: impl Fn(&Stats) -> Option<u64>) -> Option<u64> {
        let snapshot = self.snapshot.as_ref()?;
        let mut total = 0u64;
        let mut counted = false;
        for profile in snapshot.profiles.iter().filter(|profile| profile.enabled) {
            total = total.saturating_add(pick(profile.stats.as_ref()?)?);
            counted = true;
        }
        counted.then_some(total)
    }

    pub fn links(&self) -> &[Link] {
        self.snapshot
            .as_ref()
            .map_or(&[], |snapshot| snapshot.links.as_slice())
    }

    /// Whether any counters were reported at all.
    pub fn stats_available(&self) -> bool {
        self.total_rx().is_some()
    }

    /// Actions that mutate the daemon are available only while the connection is live.
    pub fn can_act(&self) -> bool {
        self.conn == Conn::Live && self.snapshot.is_some()
    }

    pub fn is_peer_owned(&self, id: &str) -> bool {
        self.peer_owned.iter().any(|held| held == id)
    }

    pub fn toggle_paused(&mut self) {
        self.paused = !self.paused;
        self.push_activity(
            if self.paused {
                "live updates paused"
            } else {
                "live updates resumed"
            },
            Tone::Muted,
        );
        self.refresh_tray();
    }

    pub fn tray_tooltip(&self) -> String {
        if self.paused {
            return "netscope · live updates paused".to_string();
        }
        match &self.conn {
            Conn::Connecting => "netscope · connecting".to_string(),
            Conn::Down(_) => "netscope · daemon down".to_string(),
            Conn::Denied(_) => "netscope · permission denied".to_string(),
            Conn::Live => match (self.total_rx(), self.total_tx()) {
                (Some(rx), Some(tx)) => {
                    format!(
                        "netscope · ↓ {} · ↑ {}",
                        fmt_rate(Some(rx)),
                        fmt_rate(Some(tx))
                    )
                }
                _ => "netscope · counters unavailable".to_string(),
            },
        }
    }

    pub fn refresh_tray(&self) {
        let Some(tray) = &self.tray else {
            return;
        };
        tray.set_tooltip(self.tray_tooltip());
        let pause = if self.paused {
            "Resume updates"
        } else {
            "Pause updates"
        };
        tray.set_menu(vec![
            rune::tray::TrayItem::action("show", "Show netscope"),
            rune::tray::TrayItem::Separator,
            rune::tray::TrayItem::action("pause", pause),
            rune::tray::TrayItem::Separator,
            rune::tray::TrayItem::action("quit", "Quit"),
        ]);
    }

    pub fn toggle_selected(&mut self) {
        if !self.can_act() {
            return;
        }
        let Some(profile) = self.selected() else {
            return;
        };
        let id = profile.id.clone();
        let enable = !profile.enabled;
        if self.demo {
            self.demo_set_enabled(&id, enable);
            return;
        }
        self.send(if enable {
            Action::Enable(id)
        } else {
            Action::Disable(id)
        });
    }

    fn demo_set_enabled(&mut self, id: &str, enable: bool) {
        if let Some(snapshot) = self.snapshot.as_mut()
            && let Some(profile) = snapshot.profiles.iter_mut().find(|p| p.id == id)
        {
            profile.enabled = enable;
            let generation = profile.generation.wrapping_add(1);
            profile.generation = generation;
            let action = if enable { "enabled" } else { "disabled" };
            self.push_activity(
                format!("{id} {action} · generation {generation}"),
                Tone::Good,
            );
            self.notice = Some(Notice {
                message: format!("{id} {action}"),
                ok: true,
            });
        }
        self.refresh_tray();
    }

    pub fn request_remove(&mut self) {
        if !self.can_act() {
            return;
        }
        self.pending_remove = self.selected_id();
    }

    pub fn cancel_remove(&mut self) {
        self.pending_remove = None;
    }

    pub fn confirm_remove(&mut self) {
        let Some(id) = self.pending_remove.take() else {
            return;
        };
        if self.demo {
            self.demo_remove(&id);
            return;
        }
        self.opening = true;
        let action = if self.is_peer_owned(&id) {
            Action::Release(id)
        } else {
            Action::Remove(id)
        };
        if !self.send(action) {
            self.opening = false;
        }
    }

    fn demo_remove(&mut self, id: &str) {
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.profiles.retain(|profile| profile.id != id);
        }
        self.peer_owned.retain(|held| held != id);
        self.clamp_selection();
        self.push_activity(format!("{id} released"), Tone::Good);
        self.notice = Some(Notice {
            message: format!("{id} released"),
            ok: true,
        });
        self.refresh_tray();
    }

    pub fn note_action_ok(&mut self, message: impl Into<String>) {
        self.opening = false;
        self.notice = Some(Notice {
            message: message.into(),
            ok: true,
        });
    }

    pub fn note_action_err(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.opening = false;
        if self.screen == Screen::Add {
            self.add_error = Some(message.clone());
        }
        self.notice = Some(Notice {
            message: message.clone(),
            ok: false,
        });
        self.push_activity(message, Tone::Bad);
    }

    pub fn note_opened(&mut self, profile: String, peer: bool) {
        self.opening = false;
        if peer {
            self.peer_owned.push(profile.clone());
        }
        self.screen = Screen::Apps;
        self.notice = Some(Notice {
            message: format!("opened {profile}"),
            ok: true,
        });
        self.push_activity(format!("{profile} opened · peer hold"), Tone::Good);
        self.refresh_tray();
    }

    pub fn dismiss_notice(&mut self) {
        self.notice = None;
    }

    pub fn set_processes(&mut self, processes: Vec<ProcInfo>) {
        self.processes = processes;
        self.scanning = false;
        self.selected_proc = 0;
    }

    pub fn begin_add(&mut self) {
        self.screen = Screen::Add;
        self.add_error = None;
        self.pending_remove = None;
        if self.add_route.is_empty() {
            if self.demo {
                self.add_route = self
                    .links()
                    .iter()
                    .filter(|link| link.up)
                    .map(|link| link.interface.clone())
                    .collect();
            } else if let Some(link) = self.links().iter().find(|link| link.up) {
                self.add_route.push(link.interface.clone());
            }
        }
        if !self.demo && self.processes.is_empty() && !self.scanning {
            self.scan_processes();
        }
    }

    pub fn scan_processes(&mut self) {
        if self.demo {
            self.processes = demo_processes();
            self.scanning = false;
            self.selected_proc = 0;
            return;
        }
        if !self.can_act() {
            self.add_error = Some("Connect to netscoped before scanning processes.".to_string());
            return;
        }
        self.scanning = true;
        if !self.send(Action::ScanProcesses) {
            self.scanning = false;
        }
    }

    pub fn add_target_label(&self) -> String {
        match self.add_source {
            AddSource::Process => self.processes.get(self.selected_proc).map_or_else(
                || "no process selected".to_string(),
                |process| format!("{} · pid {}", process.name, process.pid),
            ),
            AddSource::Executable => {
                let path = self.add_exe.text.trim();
                if path.is_empty() {
                    "no executable selected".to_string()
                } else {
                    path.to_string()
                }
            }
        }
    }

    pub fn selected_filter_cidrs(&self) -> Vec<String> {
        FILTER_CIDRS
            .iter()
            .zip(self.add_deny)
            .filter(|(_, checked)| *checked)
            .map(|(cidr, _)| (*cidr).to_string())
            .collect()
    }

    pub fn add_policy_summary(&self) -> String {
        match self.add_mode {
            crate::model::Mode::Filter => {
                let deny = self.selected_filter_cidrs();
                if deny.is_empty() {
                    "filter · allow everything".to_string()
                } else {
                    format!("filter · deny {}", deny.join(", "))
                }
            }
            crate::model::Mode::Route => {
                if self.add_route.is_empty() {
                    "route · no links chosen".to_string()
                } else {
                    format!("route {}", self.add_route.join(" → "))
                }
            }
            crate::model::Mode::Shared => "shared · existing route".to_string(),
        }
    }

    pub fn begin_open(&mut self) {
        if self.opening {
            return;
        }
        if !self.can_act() {
            self.add_error = Some("Connect to netscoped before opening a scope.".to_string());
            return;
        }
        let target = match self.add_source {
            AddSource::Process => match self.processes.get(self.selected_proc) {
                Some(process) => TargetChoice::Process {
                    pid: process.pid,
                    name: process.name.clone(),
                },
                None => {
                    self.add_error = Some("Select a process first.".to_string());
                    return;
                }
            },
            AddSource::Executable => {
                let path = self.add_exe.text.trim().to_string();
                if path.is_empty() {
                    self.add_error = Some("Enter an executable path first.".to_string());
                    return;
                }
                TargetChoice::Executable { path }
            }
        };
        let policy = match self.add_mode {
            crate::model::Mode::Filter => {
                let deny = self.selected_filter_cidrs();
                if deny.is_empty() {
                    self.add_error = Some(
                        "Choose at least one destination to deny, or use route mode.".to_string(),
                    );
                    return;
                }
                PolicyChoice::Filter { deny }
            }
            crate::model::Mode::Route => {
                if self.add_route.is_empty() {
                    self.add_error =
                        Some("Choose at least one link for a route scope.".to_string());
                    return;
                }
                PolicyChoice::Route {
                    links: self.add_route.clone(),
                }
            }
            crate::model::Mode::Shared => PolicyChoice::Shared,
        };
        let request = OpenRequest {
            target,
            policy,
            peer: self.release_on_close,
        };
        if self.demo {
            self.demo_open(request);
            return;
        }
        self.add_error = None;
        self.opening = true;
        if !self.send(Action::Open(request)) {
            self.opening = false;
        }
    }

    fn demo_open(&mut self, request: OpenRequest) {
        let (target, name) = match &request.target {
            TargetChoice::Process { name, .. } => (format!("name:{name}"), name.clone()),
            TargetChoice::Executable { path } => (path.clone(), path.clone()),
        };
        let mut id = name
            .rsplit('/')
            .next()
            .unwrap_or("scope")
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        id = id.trim_matches('-').to_string();
        if id.is_empty() {
            id = "scope".to_string();
        }
        let base = id.clone();
        let mut suffix = 2;
        while self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.profiles.iter().any(|profile| profile.id == id))
        {
            id = format!("{base}-{suffix}");
            suffix += 1;
        }
        let mode = match request.policy {
            PolicyChoice::Filter { .. } => crate::model::Mode::Filter,
            PolicyChoice::Route { .. } => crate::model::Mode::Route,
            PolicyChoice::Shared => crate::model::Mode::Shared,
        };
        let table = self.snapshot.as_ref().map_or(20_100, |snapshot| {
            20_100u32.saturating_add(snapshot.profiles.len() as u32)
        });
        let profile = Profile {
            id: id.clone(),
            mode,
            enabled: true,
            target,
            cgroup: format!("/sys/fs/cgroup/netscope/{id}"),
            cgroup_level: 2,
            pids: match &request.target {
                TargetChoice::Process { pid, .. } => vec![*pid],
                TargetChoice::Executable { .. } => Vec::new(),
            },
            nft_table: format!("inet netscope_{id}"),
            mark: "0x4e53".to_string(),
            table,
            rule_priority: 1_000,
            attached: "pre-exec".to_string(),
            healthy: true,
            warnings: Vec::new(),
            consumers: vec!["netscope-gui".to_string()],
            policies: vec![format!("netscope-gui:{}", mode.label())],
            generation: self
                .snapshot
                .as_ref()
                .map_or(1, |snapshot| snapshot.generation().wrapping_add(1)),
            stats: Some(Stats {
                since_unix: now_unix(),
                ..Stats::default()
            }),
        };
        if let Some(snapshot) = self.snapshot.as_mut() {
            snapshot.profiles.push(profile);
        }
        if request.peer {
            self.peer_owned.push(id.clone());
        }
        self.screen = Screen::Apps;
        self.selected_profile = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.profiles.len().saturating_sub(1));
        self.opening = false;
        self.add_error = None;
        self.notice = Some(Notice {
            message: format!("opened {id}"),
            ok: true,
        });
        self.push_activity(
            format!(
                "{id} opened · {}",
                if request.peer {
                    "peer hold"
                } else {
                    "persistent"
                }
            ),
            Tone::Good,
        );
        self.refresh_tray();
    }

    pub fn retry(&mut self) {
        if self.demo {
            self.demo_retry();
            return;
        }
        self.send(Action::Retry);
    }

    fn demo_retry(&mut self) {
        let tray = self.tray.take();
        let mut fresh = State::demo(tray);
        fresh.notice = Some(Notice {
            message: "demo connection restored".to_string(),
            ok: true,
        });
        *self = fresh;
    }

    pub fn refresh(&mut self) {
        if self.demo {
            self.push_activity("refresh requested", Tone::Muted);
            self.notice = Some(Notice {
                message: "demo snapshot refreshed".to_string(),
                ok: true,
            });
            return;
        }
        self.send(Action::Refresh);
    }

    pub fn add_route_entry(&mut self) {
        let interface = self.add_link.text.trim().to_string();
        if interface.is_empty() || self.add_route.iter().any(|link| link == &interface) {
            return;
        }
        self.add_route.push(interface);
        self.add_link = TextEdit::new("");
    }

    pub fn remove_route_entry(&mut self, index: usize) {
        if index < self.add_route.len() {
            self.add_route.remove(index);
        }
    }

    pub fn move_route_up(&mut self, index: usize) {
        if index > 0 && index < self.add_route.len() {
            self.add_route.swap(index - 1, index);
        }
    }

    pub fn move_route_down(&mut self, index: usize) {
        if index + 1 < self.add_route.len() {
            self.add_route.swap(index, index + 1);
        }
    }

    fn send(&mut self, action: Action) -> bool {
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(action).is_ok());
        if !sent {
            self.notice = Some(Notice {
                message: "worker is not running".to_string(),
                ok: false,
            });
        }
        sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{fmt_rate, map_status};
    use std::time::Duration;

    const OLD_DAEMON: &str = include_str!("../tests/fixtures/status-0.2.1.json");

    fn live() -> State {
        State::live(None, None)
    }

    fn demo() -> State {
        State::demo(None)
    }

    #[test]
    fn live_state_has_no_snapshot_or_counters() {
        let state = live();
        assert!(state.snapshot.is_none());
        assert_eq!(state.conn, Conn::Connecting);
        assert_eq!(state.total_rx(), None);
        assert!(!state.stats_available());
        assert!(!state.can_act());
        assert_eq!(state.tray_tooltip(), "netscope · connecting");
    }

    #[test]
    fn old_daemon_remains_live_with_unavailable_counters() {
        let data = serde_json::from_str(OLD_DAEMON).expect("fixture parses");
        let mut state = live();
        state.apply_snapshot(map_status(&data, None, Duration::from_secs(1)));
        assert_eq!(state.conn, Conn::Live);
        assert!(state.can_act());
        assert_eq!(state.total_rx(), None);
        assert_eq!(state.total_tx(), None);
        assert_eq!(state.total_pps(), None);
        assert_eq!(state.links().len(), 0);
        assert!(state.snapshot.is_some());
    }

    #[test]
    fn down_keeps_the_last_snapshot_and_marks_it_stale() {
        let mut state = demo();
        state.connection_lost(Conn::Down("daemon not running".to_string()));
        assert!(state.snapshot.is_some(), "last snapshot retained");
        assert!(state.stale);
        assert!(!state.can_act());
        assert_eq!(state.conn, Conn::Down("daemon not running".to_string()));
    }

    #[test]
    fn denied_clears_the_snapshot_and_stops_actions() {
        let mut state = demo();
        state.connection_lost(Conn::Denied("permission denied".to_string()));
        assert!(!state.stale);
        assert!(!state.can_act());
        assert!(matches!(state.conn, Conn::Denied(_)));
    }

    #[test]
    fn reconnecting_ticks_do_not_spam_a_new_line() {
        let mut state = live();
        state.connection_lost(Conn::Down("one".to_string()));
        let lines = state.activity.len();
        state.connection_lost(Conn::Down("two".to_string()));
        assert_eq!(state.activity.len(), lines);
        assert_eq!(
            state.activity[0].message,
            "daemon unreachable · retrying every 2 s"
        );
    }

    #[test]
    fn actions_are_gated_until_a_live_snapshot_exists() {
        let mut state = live();
        state.toggle_selected();
        assert_eq!(state.selected_id(), None);
        state.request_remove();
        assert_eq!(state.pending_remove, None);
        state.begin_open();
        assert_eq!(
            state.add_error.as_deref(),
            Some("Connect to netscoped before opening a scope.")
        );
        state.connection_lost(Conn::Down("down".to_string()));
        state.toggle_selected();
        assert!(!state.can_act());
    }

    #[test]
    fn selection_clamps_after_the_last_profile_is_removed() {
        let mut state = demo();
        state.screen = Screen::Apps;
        state.selected_profile = 3;
        state.request_remove();
        assert_eq!(state.pending_remove.as_deref(), Some("steam"));
        state.confirm_remove();
        assert_eq!(state.snapshot.as_ref().expect("snapshot").profiles.len(), 3);
        assert_eq!(state.selected_profile, 2);
        assert_eq!(state.selected_id().as_deref(), Some("spotify"));
    }

    #[test]
    fn disabling_a_profile_removes_it_from_the_totals() {
        let mut state = demo();
        let before = state.total_tx().expect("demo counters");
        state.selected_profile = 0;
        state.toggle_selected();
        assert!(!state.selected().expect("selected").enabled);
        assert!(state.total_tx().expect("demo counters") < before);
        assert_eq!(state.selected().expect("selected").generation, 413);
    }

    #[test]
    fn peer_owned_removal_is_labelled_release() {
        let mut state = demo();
        state.select_profile(0);
        assert!(state.is_peer_owned("overwatch"));
        state.request_remove();
        state.confirm_remove();
        assert!(!state.is_peer_owned("overwatch"));
        assert!(
            state
                .snapshot
                .as_ref()
                .expect("snapshot")
                .profiles
                .iter()
                .all(|p| p.id != "overwatch")
        );
    }

    #[test]
    fn add_validation_names_the_missing_field() {
        let mut state = demo();
        state.begin_add();
        state.add_mode = crate::model::Mode::Filter;
        state.add_deny = [false; 3];
        state.begin_open();
        assert_eq!(
            state.add_error.as_deref(),
            Some("Choose at least one destination to deny, or use route mode.")
        );
        state.add_mode = crate::model::Mode::Route;
        state.add_route.clear();
        state.begin_open();
        assert_eq!(
            state.add_error.as_deref(),
            Some("Choose at least one link for a route scope.")
        );
        state.add_source = AddSource::Executable;
        state.add_exe = TextEdit::new("");
        state.add_route.push("enp7s0f4u1".to_string());
        state.begin_open();
        assert_eq!(
            state.add_error.as_deref(),
            Some("Enter an executable path first.")
        );
    }

    #[test]
    fn adding_a_demo_scope_selects_it_and_uses_the_next_generation() {
        let mut state = demo();
        state.begin_add();
        state.add_source = AddSource::Executable;
        state.add_exe = TextEdit::new("/usr/bin/kitty");
        state.begin_open();
        let snapshot = state.snapshot.as_ref().expect("snapshot");
        assert_eq!(snapshot.profiles.len(), 5);
        let added = snapshot.profiles.last().expect("added");
        assert_eq!(added.id, "kitty");
        assert_eq!(added.target, "/usr/bin/kitty");
        assert_eq!(added.generation, 413);
        assert_eq!(state.screen, Screen::Apps);
        assert_eq!(state.selected_profile, 4);
        assert!(state.peer_owned.iter().any(|id| id == "kitty"));
    }

    #[test]
    fn route_order_moves_and_duplicates_are_refused() {
        let mut state = demo();
        state.add_route = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        state.move_route_up(2);
        assert_eq!(state.add_route, ["a", "c", "b"]);
        state.move_route_down(0);
        assert_eq!(state.add_route, ["c", "a", "b"]);
        state.add_link = TextEdit::new("a");
        state.add_route_entry();
        assert_eq!(state.add_route.len(), 3, "duplicate link refused");
        state.add_link = TextEdit::new("d");
        state.add_route_entry();
        assert_eq!(state.add_route, ["c", "a", "b", "d"]);
    }

    #[test]
    fn demo_retry_restores_a_snapshot() {
        let mut state = demo();
        state.connection_lost(Conn::Down("down".to_string()));
        state.retry();
        assert_eq!(state.conn, Conn::Live);
        assert!(state.snapshot.is_some());
    }

    #[test]
    fn formatting_is_shared_with_the_tooltip() {
        assert_eq!(fmt_rate(Some(2_020_000)), "2.02 Mb/s");
        let state = demo();
        assert_eq!(state.tray_tooltip(), "netscope · ↓ 3.87 Mb/s · ↑ 2.02 Mb/s");
    }
}
