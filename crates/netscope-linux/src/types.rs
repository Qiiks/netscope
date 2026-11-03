use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub type ProfileId = String;
pub type ConsumerId = String;

pub const MARK_BASE: u32 = 0x4e53;
pub const TABLE_BASE: u32 = 20000;
pub const PRIORITY_BASE: u32 = 1000;
pub const PRIORITY_STRIDE: u32 = 32;
pub const MAX_PROFILES: u8 = 32;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    Native { path: String, dev: u64, ino: u64 },
    Wine { path: String, dev: u64, ino: u64 },
    Name { name: String },
    Steam { app_id: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetSpec {
    Native { path: String },
    Wine { path: String },
    Name { name: String },
    Steam { app_id: u32 },
}

/// The identity a profile is shared on.
///
/// A Wine PE and a bare process name unify on the PE/process basename, so
/// Dropship can pass `Overwatch.exe` while ExitLink passes `Overwatch` and both
/// land on one profile. A native executable stays exact by inode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetKey {
    Name { name: String },
    Native { dev: u64, ino: u64 },
    Steam { app_id: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileKey {
    pub target: TargetKey,
    pub target_uid: u32,
}

impl ProfileKey {
    pub fn new(target: &Target, target_uid: u32) -> Self {
        Self {
            target: normalized_target(target),
            target_uid,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterDefault {
    Drop,
    Allow,
}

/// One consumer's networking intent for a shared profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Policy {
    Filter {
        default: FilterDefault,
        #[serde(default)]
        exceptions: Vec<String>,
    },
    Route {
        interface: String,
        gateway: Option<String>,
        gateway6: Option<String>,
        include_lan: bool,
        allow_ipv6: bool,
        /// Mark only IPv4 UDP. TCP stays on the host's normal path, which lets
        /// a TCP proxy and this route share one process.
        #[serde(default)]
        udp_only: bool,
        /// UDP destination ports that stay direct.
        #[serde(default)]
        except_ports: Vec<u16>,
        /// UDP source ports that stay direct. A socket keeps its source port
        /// for its whole life, so this pins the sockets that already existed
        /// when the route opened: rerouting a live flow would change its
        /// game-visible source and the server would drop it.
        #[serde(default)]
        except_sports: Vec<u16>,
        #[serde(default)]
        except: Vec<String>,
    },
}

/// The validated form a consumer sends. `allow_cidrs`/`deny_cidrs` keep the
/// existing CLI vocabulary; the daemon normalizes them into [`Policy`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicySpec {
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
        #[serde(default)]
        udp_only: bool,
        #[serde(default)]
        except_ports: Vec<u16>,
        #[serde(default)]
        except_sports: Vec<u16>,
        #[serde(default)]
        except: Vec<String>,
    },
}

/// Compatibility names for the single-policy CLI and older callers.
pub type Mode = Policy;
pub type ModeSpec = PolicySpec;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Hold {
    Peer,
    Persistent,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub hold: Hold,
    /// The connection that owns a peer claim. Never persisted: a peer claim
    /// cannot outlive the socket that created it.
    #[serde(skip)]
    pub connection: Option<u64>,
}

impl Claim {
    pub fn peer(connection: u64) -> Self {
        Self {
            hold: Hold::Peer,
            connection: Some(connection),
        }
    }

    pub fn persistent() -> Self {
        Self {
            hold: Hold::Persistent,
            connection: None,
        }
    }
}

/// A file the daemon learned to hold before an app can open it. Used for the
/// PE discovered from a Wine loader and for a native executable learned from
/// its first late attach.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Preopen {
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub kind: TargetKind,
    /// A loader is shared by every profile that needs it; removing one
    /// profile must not remove another profile's hold.
    #[serde(default)]
    pub shared: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Native,
    Wine,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: ProfileId,
    pub target: Target,
    pub target_uid: u32,
    pub owner_uid: u32,
    #[serde(default)]
    pub claims: BTreeMap<ConsumerId, Claim>,
    #[serde(default)]
    pub policies: BTreeMap<ConsumerId, Policy>,
    #[serde(default)]
    pub preopen: Vec<Preopen>,
    pub index: u8,
    pub mark: u32,
    pub table: u32,
    pub rule_priority: u32,
    pub enabled: bool,
    #[serde(default)]
    pub generation: u64,
    pub created_at: String,
    pub updated_at: String,
}

impl Profile {
    pub fn key(&self) -> ProfileKey {
        ProfileKey::new(&self.target, self.target_uid)
    }

    pub fn route_policy(&self) -> Option<(&ConsumerId, &Policy)> {
        self.policies
            .iter()
            .find(|(_, policy)| matches!(policy, Policy::Route { .. }))
    }

    pub fn filter_policies(&self) -> impl Iterator<Item = (&ConsumerId, &Policy)> {
        self.policies
            .iter()
            .filter(|(_, policy)| matches!(policy, Policy::Filter { .. }))
    }

    pub fn has_route(&self) -> bool {
        self.route_policy().is_some()
    }

    /// True when the profile routes and that route is scoped to UDP. Socket
    /// marking must follow it: a mark on a TCP socket would route a
    /// handshake into a UDP-only interface.
    pub fn route_is_udp_only(&self) -> bool {
        matches!(
            self.route_policy(),
            Some((_, Policy::Route { udp_only: true, .. }))
        )
    }

    /// UDP source ports whose sockets stay unmarked and direct: they existed
    /// when the route opened, and rerouting a live flow would change its
    /// game-visible source.
    pub fn route_except_sports(&self) -> Vec<u16> {
        match self.route_policy() {
            Some((_, Policy::Route { except_sports, .. })) => except_sports.clone(),
            _ => Vec::new(),
        }
    }

    pub fn has_policies(&self) -> bool {
        !self.policies.is_empty()
    }

    pub fn touch(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.updated_at = now_rfc3339();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub version: u32,
    pub profiles: BTreeMap<ProfileId, Profile>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 2,
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

pub fn consumer_id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id.chars().next().is_some_and(|c| c.is_ascii_lowercase())
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
    PRIORITY_BASE + PRIORITY_STRIDE * u32::from(index)
}

pub fn table_name(id: &str) -> String {
    format!("netscope_{}", id.replace('-', "_"))
}

pub fn normalized_target(target: &Target) -> TargetKey {
    match target {
        Target::Native { dev, ino, .. } => TargetKey::Native {
            dev: *dev,
            ino: *ino,
        },
        Target::Steam { app_id } => TargetKey::Steam { app_id: *app_id },
        Target::Name { name } => TargetKey::Name {
            name: normalize_name(name),
        },
        Target::Wine { path, .. } => TargetKey::Name {
            name: normalize_name(path),
        },
    }
}

/// Lowercase the last path component and strip `.exe`, so `Overwatch.exe`,
/// `overwatch`, and `Z:\...\Overwatch.exe` are the same identity.
pub fn normalize_name(value: &str) -> String {
    let base = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

pub fn suggest_profile_id(key: &ProfileKey) -> String {
    let raw = match &key.target {
        TargetKey::Name { name } => name.clone(),
        TargetKey::Native { dev, ino } => format!("native-{dev:x}-{ino:x}"),
        TargetKey::Steam { app_id } => format!("steam-{app_id}"),
    };
    let mut slug: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    while slug.starts_with('-') {
        slug.remove(0);
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug.truncate(24);
    if slug.is_empty() {
        slug.push_str("app");
    }
    if key.target_uid != 0 {
        let suffix = format!("-u{}", key.target_uid);
        if slug.len() + suffix.len() > 32 {
            slug.truncate(32 - suffix.len());
        }
        slug.push_str(&suffix);
    }
    slug
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
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
    fn name_targets_serde_with_kind_tag() {
        let spec = TargetSpec::Name {
            name: "Overwatch.exe".into(),
        };
        let value = serde_json::to_value(&spec).expect("serialize name spec");
        assert_eq!(value["kind"], "name");
        assert_eq!(value["name"], "Overwatch.exe");

        let target = Target::Name {
            name: "Overwatch.exe".into(),
        };
        let value = serde_json::to_value(&target).expect("serialize name target");
        assert_eq!(value["kind"], "name");
        assert_eq!(
            serde_json::from_value::<Target>(value).expect("deserialize name target"),
            target
        );
    }

    #[test]
    fn names_and_wine_paths_share_one_key() {
        let name = Target::Name {
            name: "Overwatch.exe".into(),
        };
        let wine = Target::Wine {
            path: "/games/Overwatch/Overwatch.exe".into(),
            dev: 1,
            ino: 2,
        };
        assert_eq!(ProfileKey::new(&name, 1000), ProfileKey::new(&wine, 1000));
        assert_ne!(ProfileKey::new(&name, 1000), ProfileKey::new(&name, 1001));
    }

    #[test]
    fn native_targets_stay_exact() {
        let one = Target::Native {
            path: "/a".into(),
            dev: 1,
            ino: 2,
        };
        let two = Target::Native {
            path: "/b".into(),
            dev: 1,
            ino: 3,
        };
        assert_ne!(ProfileKey::new(&one, 1000), ProfileKey::new(&two, 1000));
    }

    #[test]
    fn table_names_are_one_per_profile() {
        assert_eq!(table_name("my-game"), "netscope_my_game");
    }
}
