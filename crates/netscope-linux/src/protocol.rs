use serde::{Deserialize, Serialize};

use crate::types::{Hold, LinkStatus, PolicySpec, TargetSpec};

pub const API_VERSION: u32 = 2;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RequestOp {
    Status,
    List,
    Add(AddProfile),
    Remove {
        name: String,
    },
    Enable {
        name: String,
    },
    Disable {
        name: String,
    },
    Refresh,
    /// Register a consumer on a shared process scope. Idempotent per
    /// `(target, target_uid, consumer)`.
    Open(OpenScope),
    /// Release one consumer's claim; the profile is removed when it was the
    /// last claim.
    Close {
        profile: String,
        consumer: String,
    },
    /// Replace one consumer's policy atomically.
    SetPolicy {
        profile: String,
        consumer: String,
        policy: PolicySpec,
    },
    ClearPolicy {
        profile: String,
        consumer: String,
    },
    /// Look up a profile by id or by its shared identity.
    Resolve {
        profile: Option<String>,
        target: Option<TargetSpec>,
        target_uid: Option<u32>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub op: RequestOp,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl Response {
    pub fn ok(id: u64, data: serde_json::Value) -> Self {
        Self {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(id: u64, error: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddProfile {
    pub name: String,
    pub target: TargetSpec,
    pub mode: PolicySpec,
    pub target_uid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenScope {
    pub consumer: String,
    pub target: TargetSpec,
    pub target_uid: u32,
    #[serde(default)]
    pub name: Option<String>,
    pub hold: Hold,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeHandle {
    pub profile: String,
    pub generation: u64,
    pub target: String,
    pub target_uid: u32,
    pub state: String,
    pub attached: String,
    pub pids: Vec<u32>,
    pub consumers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloseResult {
    pub profile: String,
    pub released: bool,
    pub removed: bool,
    pub consumers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusData {
    pub api_version: u32,
    pub daemon_version: String,
    pub pid: u32,
    pub kernel: String,
    pub cgroup_root: String,
    pub state_path: String,
    pub config_path: String,
    pub profiles: Vec<ProfileStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileStatus {
    pub id: String,
    pub mode: String,
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
    #[serde(default)]
    pub consumers: Vec<String>,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub generation: u64,
    /// Ordered route links. Empty for filter-only profiles and for daemons
    /// older than 0.3.0.
    #[serde(default)]
    pub links: Vec<LinkStatus>,
}
