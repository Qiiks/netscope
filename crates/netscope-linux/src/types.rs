use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub type ProfileId = String;

pub const MARK_BASE: u32 = 0x4e53;
pub const TABLE_BASE: u32 = 20000;
pub const PRIORITY_BASE: u32 = 1000;
pub const MAX_PROFILES: u8 = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Native { path: String, dev: u64, ino: u64 },
    Wine { path: String, dev: u64, ino: u64 },
    Steam { app_id: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetSpec {
    Native { path: String },
    Wine { path: String },
    Steam { app_id: u32 },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterDefault {
    Drop,
    Allow,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mode {
    Filter {
        default: FilterDefault,
        exceptions: Vec<String>,
    },
    Route {
        interface: String,
        gateway: Option<String>,
        gateway6: Option<String>,
        include_lan: bool,
        allow_ipv6: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModeSpec {
    Filter {
        default: FilterDefault,
        #[serde(default)]
        allow_cidrs: Vec<String>,
        #[serde(default)]
        deny_cidrs: Vec<String>,
    },
    Route {
        interface: String,
        gateway: Option<String>,
        gateway6: Option<String>,
        #[serde(default)]
        include_lan: bool,
        #[serde(default)]
        allow_ipv6: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: ProfileId,
    pub target: Target,
    pub target_uid: u32,
    pub owner_uid: u32,
    pub mode: Mode,
    pub index: u8,
    pub mark: u32,
    pub table: u32,
    pub rule_priority: u32,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub version: u32,
    pub profiles: BTreeMap<ProfileId, Profile>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub cgroup_root: PathBuf,
    pub poll_interval_ms: u64,
    pub refresh_interval_secs: u64,
    pub max_profiles: u8,
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/netscope/control.sock"),
            state_path: PathBuf::from("/var/lib/netscope/state.json"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup/netscope"),
            poll_interval_ms: 1000,
            refresh_interval_secs: 5,
            max_profiles: MAX_PROFILES,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachSource {
    PreExec,
    PreOpen,
    Late,
}

#[derive(Clone, Debug)]
pub struct DoctorArgs {
    pub socket: Option<PathBuf>,
    pub json: bool,
}

#[derive(Clone, Debug)]
pub struct BundleArgs {
    pub socket: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

pub fn profile_id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn mark(index: u8) -> u32 {
    MARK_BASE + u32::from(index)
}

pub fn table(index: u8) -> u32 {
    TABLE_BASE + u32::from(index)
}

pub fn rule_priority(index: u8) -> u32 {
    PRIORITY_BASE + u32::from(index)
}

pub fn table_name(mode: &Mode, id: &str) -> String {
    let prefix = match mode {
        Mode::Filter { .. } => "netscope_filter",
        Mode::Route { .. } => "netscope_route",
    };
    format!("{prefix}_{}", id.replace('-', "_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ids_are_conservative() {
        assert!(profile_id_valid("game"));
        assert!(profile_id_valid("game-1"));
        assert!(!profile_id_valid(""));
        assert!(!profile_id_valid("Game"));
        assert!(!profile_id_valid("-game"));
        assert!(!profile_id_valid("a".repeat(33).as_str()));
    }

    #[test]
    fn wine_targets_serde_with_kind_tag() {
        let spec = TargetSpec::Wine {
            path: "/games/foo.exe".into(),
        };
        let value = serde_json::to_value(&spec).expect("serialize wine spec");
        assert_eq!(value["kind"], "wine");

        let target = Target::Wine {
            path: "/games/foo.exe".into(),
            dev: 42,
            ino: 7,
        };
        let value = serde_json::to_value(&target).expect("serialize wine target");
        assert_eq!(value["kind"], "wine");
        assert_eq!(
            serde_json::from_value::<Target>(value).expect("deserialize wine target"),
            target
        );
    }

    #[test]
    fn table_names_replace_dashes() {
        let id = "my-game";
        let mode = Mode::Filter {
            default: FilterDefault::Drop,
            exceptions: vec![],
        };
        assert_eq!(table_name(&mode, id), "netscope_filter_my_game");
    }
}
