use std::path::Path;

use ipnet::IpNet;
use serde_json::Value;
use thiserror::Error;

use crate::command::run;
use crate::types::{FilterDefault, Mode, Profile};

#[derive(Debug, Error)]
pub enum NftError {
    #[error("nft command failed: {0}")]
    Command(#[from] anyhow::Error),
    #[error("invalid exception network {0}")]
    InvalidCidr(String),
}

#[derive(Debug)]
pub struct NftManager {
    relative_root: String,
    level: u32,
}

impl NftManager {
    pub fn new(cgroup_root: &Path) -> Result<Self, NftError> {
        let relative = cgroup_root
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| NftError::Command(anyhow::anyhow!("cgroup root outside cgroup2")))?
            .to_string_lossy()
            .trim_matches('/')
            .to_string();
        let level = relative.split('/').filter(|part| !part.is_empty()).count() as u32 + 1;
        Ok(Self {
            relative_root: relative,
            level,
        })
    }

    pub fn level(&self) -> u32 {
        self.level
    }

    pub fn relative_root(&self) -> &str {
        &self.relative_root
    }

    pub fn cgroup_selector(&self, id: &str) -> String {
        format!(
            "socket cgroupv2 level {} \"{}/{}\"",
            self.level, self.relative_root, id
        )
    }

    pub fn table_name(profile: &Profile) -> String {
        crate::types::table_name(&profile.mode, &profile.id)
    }

    pub fn exists(&self, profile: &Profile) -> Result<bool, NftError> {
        let name = Self::table_name(profile);
        Ok(self.list_tables()?.iter().any(|table| table == &name))
    }

    pub fn list_tables(&self) -> Result<Vec<String>, NftError> {
        let output = run("nft", &["-j", "list", "tables"], None)?;
        let value: Value = serde_json::from_slice(&output.stdout)
            .map_err(|err| NftError::Command(anyhow::anyhow!("parse nft tables: {err}")))?;
        Ok(parse_table_names(&value))
    }

    pub fn apply(&self, profile: &Profile) -> Result<(), NftError> {
        let name = Self::table_name(profile);
        let selector = self.cgroup_selector(&profile.id);
        let body = self.render_body(profile, &selector)?;
        let script = if self.exists(profile)? {
            format!("flush table inet {name}\ntable inet {name} {{\n{body}}}\n")
        } else {
            format!("add table inet {name}\ntable inet {name} {{\n{body}}}\n")
        };
        run("nft", &["-f", "-"], Some(script.as_bytes()))?;
        Ok(())
    }

    pub fn remove(&self, profile: &Profile) -> Result<(), NftError> {
        if !self.exists(profile)? {
            return Ok(());
        }
        let name = Self::table_name(profile);
        run("nft", &["delete", "table", "inet", &name], None)?;
        Ok(())
    }

    fn render_body(&self, profile: &Profile, selector: &str) -> Result<String, NftError> {
        match &profile.mode {
            Mode::Filter {
                default,
                exceptions,
            } => {
                let mut lines = Vec::new();
                match default {
                    FilterDefault::Drop => {
                        lines.push(format!(
                            "    {selector} meta nfproto ipv4 ip daddr 127.0.0.0/8 accept"
                        ));
                        lines.push(format!(
                            "    {selector} meta nfproto ipv6 ip6 daddr ::1/128 accept"
                        ));
                        for exception in exceptions {
                            lines.push(format!("    {selector} {}", render_address(exception)?));
                        }
                        lines.push(format!("    {selector} counter drop"));
                    }
                    FilterDefault::Allow => {
                        for exception in exceptions {
                            lines.push(format!(
                                "    {selector} {} counter drop",
                                render_address(exception)?
                            ));
                        }
                    }
                }
                Ok(chain("filter", "filter", &lines))
            }
            Mode::Route {
                interface: _,
                gateway: _,
                gateway6: _,
                include_lan,
                allow_ipv6,
            } => {
                let mut lines = vec![
                    format!("    {selector} meta nfproto ipv4 ip daddr 127.0.0.0/8 accept"),
                    format!("    {selector} meta nfproto ipv6 ip6 daddr ::1/128 accept"),
                ];
                if !include_lan {
                    lines.push(format!(
                        "    {selector} meta nfproto ipv4 ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 }} accept"
                    ));
                    lines.push(format!(
                        "    {selector} meta nfproto ipv6 ip6 daddr {{ fc00::/7, fe80::/10, ff00::/8 }} accept"
                    ));
                }
                if !allow_ipv6 {
                    lines.push(format!("    {selector} meta nfproto ipv6 counter drop"));
                }
                lines.push(format!(
                    "    {selector} counter meta mark set 0x{:x}",
                    profile.mark
                ));
                Ok(chain("route", "mangle", &lines))
            }
        }
    }
}

fn chain(hook: &str, priority: &str, lines: &[String]) -> String {
    let body = lines.join("\n");
    format!(
        "  chain output {{\n    type {hook} hook output priority {priority}; policy accept;\n{body}\n  }}\n"
    )
}

fn render_address(cidr: &str) -> Result<String, NftError> {
    let net: IpNet = cidr
        .parse()
        .map_err(|_| NftError::InvalidCidr(cidr.to_string()))?;
    match net {
        IpNet::V4(net) => Ok(format!("meta nfproto ipv4 ip daddr {net}")),
        IpNet::V6(net) => Ok(format!("meta nfproto ipv6 ip6 daddr {net}")),
    }
}

fn parse_table_names(value: &Value) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nft_table_json() {
        let value: Value = serde_json::from_str(
            r#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"netscope_filter_game"}}]}"#,
        )
        .unwrap();
        assert_eq!(parse_table_names(&value), vec!["netscope_filter_game"]);
    }

    #[test]
    fn selector_uses_computed_level_and_root() {
        let manager = NftManager::new(Path::new("/sys/fs/cgroup/netscope")).unwrap();
        assert_eq!(manager.level(), 2);
        assert_eq!(
            manager.cgroup_selector("game"),
            "socket cgroupv2 level 2 \"netscope/game\""
        );
    }

    #[test]
    fn address_renderer_splits_families() {
        assert_eq!(
            render_address("1.1.1.1/32").unwrap(),
            "meta nfproto ipv4 ip daddr 1.1.1.1/32"
        );
        assert_eq!(
            render_address("2001:db8::/32").unwrap(),
            "meta nfproto ipv6 ip6 daddr 2001:db8::/32"
        );
    }
}
