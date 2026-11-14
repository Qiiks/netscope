//! View model for the netscope GUI.
//!
//! `StatusData` is mapped into owned screen data here, and only here. Formatting and the
//! demonstration snapshot live beside it so live and demo screens share one vocabulary.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use netscope_client::{ProfileStatus, StatusData};

/// How a profile enforces traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Route,
    Filter,
    Shared,
}

impl Mode {
    pub fn from_status(value: &str) -> Mode {
        match value {
            "route" => Mode::Route,
            "filter" => Mode::Filter,
            _ => Mode::Shared,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Route => "route",
            Mode::Filter => "filter",
            Mode::Shared => "shared",
        }
    }
}

/// The tone of one activity line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Muted,
}

/// One line in the recent-activity panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activity {
    pub time: String,
    pub message: String,
    pub tone: Tone,
}

impl Activity {
    pub fn now(message: impl Into<String>, tone: Tone) -> Activity {
        Activity {
            time: clock_now(),
            message: message.into(),
            tone,
        }
    }
}

/// Counters for one profile. `None` rates mean the daemon did not report counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub tx_bps: Option<u64>,
    pub rx_bps: Option<u64>,
    pub tx_pps: u64,
    pub rx_pps: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub routed_bytes: u64,
    pub dropped_packets: u64,
    pub since_unix: u64,
}

impl Stats {
    pub fn packet_rate(&self) -> u64 {
        self.tx_pps.saturating_add(self.rx_pps)
    }
}

/// One profile as the screens read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub mode: Mode,
    pub enabled: bool,
    pub target: String,
    pub cgroup: String,
    pub cgroup_level: u32,
    pub pids: Vec<u32>,
    pub nft_table: String,
    pub mark: String,
    pub table: u32,
    pub rule_priority: u32,
    pub attached: String,
    pub healthy: bool,
    pub warnings: Vec<String>,
    pub consumers: Vec<String>,
    pub policies: Vec<String>,
    pub generation: u64,
    pub stats: Option<Stats>,
}

impl Profile {
    pub fn packet_rate(&self) -> Option<u64> {
        self.stats.as_ref().map(Stats::packet_rate)
    }

    pub fn dropped(&self) -> Option<u64> {
        self.stats.as_ref().map(|s| s.dropped_packets)
    }
}

/// One link as the overview reads it. Populated from `ProfileStatus.links` after integration;
/// the demonstration snapshot carries the same shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub interface: String,
    pub gateway: Option<String>,
    pub gateway6: Option<String>,
    pub up: bool,
    pub active: bool,
    pub rtt_ms: Option<u32>,
    pub last_ok_unix: Option<u64>,
}

impl Link {
    pub fn role(&self) -> &'static str {
        if !self.up {
            "down"
        } else if self.active {
            "active"
        } else {
            "standby"
        }
    }
}

/// One daemon status snapshot, in the form the screens draw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub api_version: u32,
    pub daemon_version: String,
    pub kernel: String,
    pub cgroup_root: String,
    pub config_path: String,
    pub state_path: String,
    pub profiles: Vec<Profile>,
    pub links: Vec<Link>,
    pub captured_at: SystemTime,
}

impl Snapshot {
    pub fn generation(&self) -> u64 {
        self.profiles
            .iter()
            .map(|p| p.generation)
            .max()
            .unwrap_or(0)
    }

    pub fn enabled_count(&self) -> usize {
        self.profiles.iter().filter(|p| p.enabled).count()
    }
}

/// Map one daemon status document into screen data.
///
/// `previous` and `elapsed` are the basis for derived rates when the daemon reports cumulative
/// counters. They are unused until the 0.3 status fields land; keeping them here means the
/// integration changes one place, not every screen.
pub fn map_status(data: &StatusData, previous: Option<&Snapshot>, elapsed: Duration) -> Snapshot {
    let profiles: Vec<Profile> = data.profiles.iter().map(map_profile).collect();
    let snapshot = Snapshot {
        api_version: data.api_version,
        daemon_version: data.daemon_version.clone(),
        kernel: data.kernel.clone(),
        cgroup_root: data.cgroup_root.clone(),
        config_path: data.config_path.clone(),
        state_path: data.state_path.clone(),
        profiles,
        links: Vec::new(),
        captured_at: SystemTime::now(),
    };
    // TODO(integration-0.3): read `ProfileStatus::links` and `ProfileStatus::stats` here;
    // derive per-profile rates from `previous` and `elapsed`, and fill `links`/`stats`.
    let _ = (previous, elapsed);
    snapshot
}

fn map_profile(profile: &ProfileStatus) -> Profile {
    Profile {
        id: profile.id.clone(),
        mode: Mode::from_status(&profile.mode),
        enabled: profile.enabled,
        target: profile.target.clone(),
        cgroup: profile.cgroup.clone(),
        cgroup_level: profile.cgroup_level,
        pids: profile.pids.clone(),
        nft_table: profile.nft_table.clone(),
        mark: profile.mark.clone(),
        table: profile.table,
        rule_priority: profile.rule_priority,
        attached: profile.attached.clone(),
        healthy: profile.healthy,
        warnings: profile.warnings.clone(),
        consumers: profile.consumers.clone(),
        policies: profile.policies.clone(),
        generation: profile.generation,
        stats: None,
    }
}

/// One process the Add screen can scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub uid: u32,
    pub cgroup: String,
}

/// A deterministic demonstration network used only by `--demo` and `--snap`.
pub fn demo_snapshot() -> Snapshot {
    let now = now_unix();
    Snapshot {
        api_version: 2,
        daemon_version: "0.2.1".to_string(),
        kernel: "7.3.3-1-cachyos".to_string(),
        cgroup_root: "/sys/fs/cgroup/netscope".to_string(),
        config_path: "/etc/netscope/config.toml".to_string(),
        state_path: "/var/lib/netscope/state.json".to_string(),
        profiles: demo_profiles(),
        links: demo_links(now),
        captured_at: SystemTime::now(),
    }
}

fn demo_profiles() -> Vec<Profile> {
    vec![
        Profile {
            id: "overwatch".to_string(),
            mode: Mode::Route,
            enabled: true,
            target: "/usr/bin/wine".to_string(),
            cgroup: "/sys/fs/cgroup/netscope/overwatch".to_string(),
            cgroup_level: 2,
            pids: vec![41221, 41290],
            nft_table: "inet netscope_overwatch".to_string(),
            mark: "0x4e53".to_string(),
            table: 20_000,
            rule_priority: 1_000,
            attached: "pre-exec".to_string(),
            healthy: true,
            warnings: vec![
                "enp7s0f4u1 has a 1500-byte MTU; route profiles are built for 1450.".to_string(),
            ],
            consumers: vec!["games".to_string()],
            policies: vec!["games:route".to_string()],
            generation: 412,
            stats: Some(Stats {
                tx_bps: Some(1_420_000),
                rx_bps: Some(680_000),
                tx_pps: 892,
                rx_pps: 774,
                tx_bytes: 8_412_000_000,
                rx_bytes: 3_180_000_000,
                tx_packets: 5_840_211,
                rx_packets: 3_191_044,
                routed_bytes: 11_592_000_000,
                dropped_packets: 0,
                since_unix: now_unix().saturating_sub(7_320),
            }),
        },
        Profile {
            id: "browser".to_string(),
            mode: Mode::Filter,
            enabled: true,
            target: "/usr/lib/firefox/firefox".to_string(),
            cgroup: "/sys/fs/cgroup/netscope/browser".to_string(),
            cgroup_level: 2,
            pids: vec![2210, 2215, 2219, 2231, 2240, 2244],
            nft_table: "inet netscope_browser".to_string(),
            mark: "0x4e44".to_string(),
            table: 20_001,
            rule_priority: 1_000,
            attached: "pre-open".to_string(),
            healthy: true,
            warnings: vec!["6 processes joined after start".to_string()],
            consumers: vec!["browser".to_string()],
            policies: vec!["browser:filter".to_string()],
            generation: 412,
            stats: Some(Stats {
                tx_bps: Some(280_000),
                rx_bps: Some(2_900_000),
                tx_pps: 410,
                rx_pps: 1_884,
                tx_bytes: 991_000_000,
                rx_bytes: 9_830_000_000,
                tx_packets: 822_442,
                rx_packets: 9_180_221,
                routed_bytes: 10_821_000_000,
                dropped_packets: 148,
                since_unix: now_unix().saturating_sub(9_900),
            }),
        },
        Profile {
            id: "spotify".to_string(),
            mode: Mode::Shared,
            enabled: true,
            target: "/usr/bin/spotify".to_string(),
            cgroup: "/sys/fs/cgroup/netscope/spotify".to_string(),
            cgroup_level: 2,
            pids: vec![8812, 8816, 8820],
            nft_table: "inet netscope_spotify".to_string(),
            mark: "0x4e53".to_string(),
            table: 20_002,
            rule_priority: 1_000,
            attached: "late".to_string(),
            healthy: true,
            warnings: Vec::new(),
            consumers: vec!["audio".to_string()],
            policies: vec!["audio:route".to_string()],
            generation: 412,
            stats: Some(Stats {
                tx_bps: Some(320_000),
                rx_bps: Some(290_000),
                tx_pps: 58,
                rx_pps: 62,
                tx_bytes: 212_000_000,
                rx_bytes: 190_000_000,
                tx_packets: 318_004,
                rx_packets: 291_772,
                routed_bytes: 402_000_000,
                dropped_packets: 0,
                since_unix: now_unix().saturating_sub(12_300),
            }),
        },
        Profile {
            id: "steam".to_string(),
            mode: Mode::Filter,
            enabled: false,
            target: "/usr/bin/steam".to_string(),
            cgroup: "/sys/fs/cgroup/netscope/steam".to_string(),
            cgroup_level: 2,
            pids: Vec::new(),
            nft_table: String::new(),
            mark: "0x4e53".to_string(),
            table: 0,
            rule_priority: 1_000,
            attached: "none".to_string(),
            healthy: true,
            warnings: Vec::new(),
            consumers: vec!["launcher".to_string()],
            policies: vec!["launcher:filter".to_string()],
            generation: 409,
            stats: Some(Stats {
                tx_bps: Some(0),
                rx_bps: Some(0),
                tx_pps: 0,
                rx_pps: 0,
                tx_bytes: 0,
                rx_bytes: 0,
                tx_packets: 0,
                rx_packets: 0,
                routed_bytes: 0,
                dropped_packets: 0,
                since_unix: now_unix().saturating_sub(14_000),
            }),
        },
    ]
}

fn demo_links(now: u64) -> Vec<Link> {
    vec![
        Link {
            interface: "enp7s0f4u1".to_string(),
            gateway: Some("192.168.1.1".to_string()),
            gateway6: Some("fe80::1".to_string()),
            up: true,
            active: true,
            rtt_ms: Some(14),
            last_ok_unix: Some(now.saturating_sub(12)),
        },
        Link {
            interface: "wlan0".to_string(),
            gateway: Some("192.168.1.1".to_string()),
            gateway6: None,
            up: true,
            active: false,
            rtt_ms: Some(31),
            last_ok_unix: Some(now.saturating_sub(12)),
        },
        Link {
            interface: "enp5s0".to_string(),
            gateway: None,
            gateway6: None,
            up: false,
            active: false,
            rtt_ms: None,
            last_ok_unix: Some(now.saturating_sub(2_460)),
        },
    ]
}

/// Processes shown by the demonstration Add screen.
pub fn demo_processes() -> Vec<ProcInfo> {
    vec![
        ProcInfo {
            pid: 41_221,
            name: "Overwatch.exe".to_string(),
            exe: "/usr/bin/wine".to_string(),
            uid: 1000,
            cgroup: "/user.slice/user-1000.slice/session-3.scope".to_string(),
        },
        ProcInfo {
            pid: 2_210,
            name: "firefox".to_string(),
            exe: "/usr/lib/firefox/firefox".to_string(),
            uid: 1000,
            cgroup: "/user.slice/user-1000.slice/app.slice/firefox.scope".to_string(),
        },
        ProcInfo {
            pid: 8_812,
            name: "spotify".to_string(),
            exe: "/usr/bin/spotify".to_string(),
            uid: 1000,
            cgroup: "/user.slice/user-1000.slice/app.slice/spotify.scope".to_string(),
        },
        ProcInfo {
            pid: 3_301,
            name: "steam".to_string(),
            exe: "/usr/bin/steam".to_string(),
            uid: 1000,
            cgroup: "/user.slice/user-1000.slice/app.slice/steam.scope".to_string(),
        },
        ProcInfo {
            pid: 22_190,
            name: "dolphin".to_string(),
            exe: "/usr/bin/dolphin".to_string(),
            uid: 1000,
            cgroup: "/user.slice/user-1000.slice/app.slice/dolphin.scope".to_string(),
        },
    ]
}

/// Demonstration activity, in the same shape live events use.
pub fn demo_activity() -> Vec<Activity> {
    vec![
        Activity {
            time: "14:31:52".to_string(),
            message: "overwatch attached · exec · pid 41221".to_string(),
            tone: Tone::Good,
        },
        Activity {
            time: "14:30:17".to_string(),
            message: "browser · 6 processes joined after start".to_string(),
            tone: Tone::Warn,
        },
        Activity {
            time: "14:28:03".to_string(),
            message: "spotify poll refreshed · 3 pids".to_string(),
            tone: Tone::Muted,
        },
        Activity {
            time: "14:12:44".to_string(),
            message: "wlan0 kept as failover · 0 switches in 24 h".to_string(),
            tone: Tone::Muted,
        },
    ]
}

/// A seeded shape for the demonstration throughput sparkline.
pub fn demo_spark() -> Vec<f32> {
    vec![
        0.32, 0.41, 0.38, 0.52, 0.47, 0.61, 0.58, 0.44, 0.51, 0.66, 0.72, 0.63, 0.55, 0.48, 0.59,
        0.71, 0.68, 0.57, 0.62, 0.74, 0.80, 0.69, 0.61, 0.58, 0.66, 0.79, 0.83, 0.71, 0.64, 0.60,
        0.55, 0.49, 0.58, 0.67, 0.73, 0.78, 0.70, 0.62, 0.57, 0.52,
    ]
}

/// A rate in bits per second, or `unavailable` when the daemon reported no counters.
pub fn fmt_rate(bps: Option<u64>) -> String {
    let Some(bps) = bps else {
        return "unavailable".to_string();
    };
    let bits = bps as f64;
    if bits >= 1_000_000_000.0 {
        format!("{:.2} Gb/s", bits / 1_000_000_000.0)
    } else if bits >= 1_000_000.0 {
        format!("{:.2} Mb/s", bits / 1_000_000.0)
    } else if bits >= 1_000.0 {
        format!("{:.1} kb/s", bits / 1_000.0)
    } else {
        format!("{bps} b/s")
    }
}

/// A byte count in decimal units.
#[cfg(test)]
pub fn fmt_bytes(bytes: u64) -> String {
    let value = bytes as f64;
    if value >= 1_000_000_000.0 {
        format!("{:.2} GB", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.1} MB", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1} KB", value / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

/// A packet or event count, or `unavailable`.
pub fn fmt_count(value: Option<u64>) -> String {
    let Some(value) = value else {
        return "unavailable".to_string();
    };
    let value = value as f64;
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}k", value / 1_000.0)
    } else {
        format!("{}", value as u64)
    }
}

/// A round-trip time, or `—` when the link has not reported one.
pub fn fmt_rtt(rtt_ms: Option<u32>) -> String {
    rtt_ms.map_or_else(|| "—".to_string(), |rtt| format!("{rtt} ms"))
}

/// How long ago a Unix timestamp was, relative to `now`.
pub fn fmt_age(last_unix: Option<u64>, now: u64) -> String {
    let Some(last) = last_unix else {
        return "never".to_string();
    };
    let secs = now.saturating_sub(last);
    if secs < 60 {
        format!("{secs} s ago")
    } else if secs < 3_600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} h ago", secs / 3_600)
    } else {
        format!("{} d ago", secs / 86_400)
    }
}

/// Seconds since the Unix epoch, saturating at zero.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A wall-clock time in UTC, `HH:MM:SSZ`.
pub fn clock_now() -> String {
    format_clock(SystemTime::now())
}

/// A timestamp in UTC, `HH:MM:SSZ`.
pub fn format_clock(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86_400;
    format!(
        "{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs % 3_600) / 60,
        secs % 60
    )
}

/// How long ago a snapshot was taken.
pub fn snapshot_age(time: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(time)
        .unwrap_or_default()
        .as_secs();
    if secs < 2 {
        "just now".to_string()
    } else if secs < 60 {
        format!("{secs} s ago")
    } else {
        format!("{} min ago", secs / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_DAEMON: &str = include_str!("../tests/fixtures/status-0.2.1.json");

    #[test]
    fn rates_cover_every_unit_and_unavailable() {
        assert_eq!(fmt_rate(None), "unavailable");
        assert_eq!(fmt_rate(Some(0)), "0 b/s");
        assert_eq!(fmt_rate(Some(940)), "940 b/s");
        assert_eq!(fmt_rate(Some(2_020_000)), "2.02 Mb/s");
        assert_eq!(fmt_rate(Some(3_100_000_000)), "3.10 Gb/s");
    }

    #[test]
    fn byte_and_count_units_read_in_decimal() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1_500), "1.5 KB");
        assert_eq!(fmt_bytes(148_000_000), "148.0 MB");
        assert_eq!(fmt_count(Some(4_080)), "4.1k");
        assert_eq!(fmt_count(None), "unavailable");
    }

    #[test]
    fn old_daemon_status_maps_without_counters_or_links() {
        let data: StatusData =
            serde_json::from_str(OLD_DAEMON).expect("captured 0.2.1 status is valid");
        let snapshot = map_status(&data, None, Duration::from_secs(1));
        assert_eq!(snapshot.profiles.len(), 1);
        let profile = &snapshot.profiles[0];
        assert_eq!(profile.id, "dropship-overwatch");
        assert_eq!(profile.mode, Mode::Filter);
        assert_eq!(profile.target, "name:Overwatch.exe");
        assert_eq!(profile.consumers, ["dropship"]);
        assert!(profile.stats.is_none(), "0.2.1 reports no counters");
        assert!(snapshot.links.is_empty(), "0.2.1 reports no links");
        assert_eq!(snapshot.generation(), 180_758);
    }

    #[test]
    fn demonstration_totals_match_the_profile_sums() {
        let snapshot = demo_snapshot();
        let enabled: Vec<&Profile> = snapshot.profiles.iter().filter(|p| p.enabled).collect();
        assert_eq!(enabled.len(), 3);
        let tx: u64 = enabled
            .iter()
            .filter_map(|p| p.stats.as_ref().and_then(|s| s.tx_bps))
            .sum();
        let rx: u64 = enabled
            .iter()
            .filter_map(|p| p.stats.as_ref().and_then(|s| s.rx_bps))
            .sum();
        assert_eq!(tx, 2_020_000);
        assert_eq!(rx, 3_870_000);
    }
}
