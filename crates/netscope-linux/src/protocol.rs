use serde::{Deserialize, Serialize};

use crate::types::{ModeSpec, TargetSpec};

pub const API_VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RequestOp {
    Status,
    List,
    Add(AddProfile),
    Remove { name: String },
    Enable { name: String },
    Disable { name: String },
    Refresh,
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
    pub mode: ModeSpec,
    pub target_uid: u32,
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
    pub pids: Vec<u32>,
    pub nft_table: String,
    pub mark: String,
    pub table: u32,
    pub rule_priority: u32,
    pub attached: String,
    pub healthy: bool,
    pub warnings: Vec<String>,
}
