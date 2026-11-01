use std::path::Path;

use ipnet::IpNet;
use serde_json::Value;
use thiserror::Error;

use crate::command::run;
use crate::types::{FilterDefault, Policy, Profile};

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

    /// Selects the profile cgroup and, separately, a socket already carrying
    /// its mark.
    ///
    /// The mark selector covers sockets that predate the cgroup attach: their
    /// cgroup is fixed at creation, but [`crate::sockets::set_mark`] changes
    /// the mark on the socket itself. The two expressions are emitted as
    /// separate rules because nftables does not compose `socket cgroupv2`
    /// with `socket mark` under `or`.
    pub fn profile_selectors(&self, profile: &Profile) -> [String; 2] {
        [
            self.cgroup_selector(&profile.id),
            format!("socket mark 0x{:x}", profile.mark),
        ]
    }

    pub fn table_name(profile: &Profile) -> String {
        crate::types::table_name(&profile.id)
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
        if !profile.has_policies() {
            return self.remove(profile);
        }
        let name = Self::table_name(profile);
        let selectors = self.profile_selectors(profile);
        let body = Self::render_body(profile, &selectors)?;
        // Flushing keeps the old chain declaration; a policy change from filter
        // to route then fails with "chain already exists". Recreate the table.
        let script = if self.exists(profile)? {
            format!("delete table inet {name}\ntable inet {name} {{\n{body}}}\n")
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

    fn render_body(profile: &Profile, selectors: &[String]) -> Result<String, NftError> {
        let mut rules = Vec::new();

        // A drop from Dropship wins over ExitLink's route, but an allowed
        // destination falls through so the route mark still applies.
        for (_, policy) in profile.filter_policies() {
            match policy {
                Policy::Filter {
                    default,
                    exceptions,
                } => match default {
                    FilterDefault::Drop => {
                        let (v4, v6) = split_addresses(exceptions)?;
                        if v4.is_empty() {
                            rules.push("meta nfproto ipv4 counter drop".to_string());
                        } else {
                            rules.push(format!(
                                "meta nfproto ipv4 ip daddr != {{ {} }} counter drop",
                                v4.join(", ")
                            ));
                        }
                        if v6.is_empty() {
                            rules.push("meta nfproto ipv6 counter drop".to_string());
                        } else {
                            rules.push(format!(
                                "meta nfproto ipv6 ip6 daddr != {{ {} }} counter drop",
                                v6.join(", ")
                            ));
                        }
                        rules.push("meta nfproto != { ipv4, ipv6 } counter drop".to_string());
                    }
                    FilterDefault::Allow => {
                        for exception in exceptions {
                            rules.push(format!("{} counter drop", render_address(exception)?));
                        }
                    }
                },
                Policy::Route { .. } => unreachable!("filter_policies only yields filters"),
            }
        }

        if let Some((
            _,
            Policy::Route {
                interface: _,
                gateway: _,
                gateway6: _,
                include_lan,
                allow_ipv6,
                udp_only,
                except_ports,
                ..
            },
        )) = profile.route_policy()
        {
            rules.push("meta nfproto ipv4 ip daddr 127.0.0.0/8 accept".to_string());
            rules.push("meta nfproto ipv6 ip6 daddr ::1/128 accept".to_string());
            if !include_lan {
                rules.push("meta nfproto ipv4 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 } accept".to_string());
                rules.push(
                    "meta nfproto ipv6 ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } accept"
                        .to_string(),
                );
            }
            if !allow_ipv6 {
                rules.push("meta nfproto ipv6 counter drop".to_string());
            }
            let selector = if *udp_only {
                if !except_ports.is_empty() {
                    let ports = except_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    rules.push(format!(
                        "meta nfproto ipv4 meta l4proto udp udp dport {{ {ports} }} accept"
                    ));
                }
                "meta nfproto ipv4 meta l4proto udp "
            } else {
                ""
            };
            rules.push(format!(
                "{selector}counter meta mark set 0x{:x}",
                profile.mark
            ));
        }

        // A route chain reroutes after the mark is set; a filter chain does
        // not, so cgroup-marked packets would keep their original route.
        let (kind, priority) = if profile.has_route() {
            ("route", "mangle")
        } else {
            ("filter", "filter")
        };
        Ok(chain(kind, priority, &expand(selectors, &rules)))
    }
}

fn expand(selectors: &[String], rules: &[String]) -> Vec<String> {
    selectors
        .iter()
        .flat_map(|selector| {
            rules
                .iter()
                .map(move |rule| format!("    {selector} {rule}"))
        })
        .collect()
}

fn chain(hook: &str, priority: &str, lines: &[String]) -> String {
    let body = lines.join("\n");
    format!(
        "  chain output {{\n    type {hook} hook output priority {priority}; policy accept;\n{body}\n  }}\n"
    )
}

fn split_addresses(cidrs: &[String]) -> Result<(Vec<String>, Vec<String>), NftError> {
    let mut v4 = vec!["127.0.0.0/8".to_string()];
    let mut v6 = vec!["::1/128".to_string()];
    for cidr in cidrs {
        let net: IpNet = cidr
            .parse()
            .map_err(|_| NftError::InvalidCidr(cidr.clone()))?;
        match net {
            IpNet::V4(net) => v4.push(net.to_string()),
            IpNet::V6(net) => v6.push(net.to_string()),
        }
    }
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    Ok((v4, v6))
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
    use crate::types::{Claim, FilterDefault, Hold, Profile, Target};

    fn profile(policies: Vec<(&str, Policy)>) -> Profile {
        let mut profile = Profile {
            id: "game".to_string(),
            target: Target::Name {
                name: "game".to_string(),
            },
            target_uid: 1000,
            owner_uid: 1000,
            claims: [(
                "cli".to_string(),
                Claim {
                    hold: Hold::Persistent,
                    connection: None,
                },
            )]
            .into(),
            policies: Default::default(),
            preopen: Vec::new(),
            index: 0,
            mark: 0x4e53,
            table: 20000,
            rule_priority: 1000,
            enabled: true,
            generation: 0,
            created_at: "0".to_string(),
            updated_at: "0".to_string(),
        };
        for (consumer, policy) in policies {
            profile.policies.insert(consumer.to_string(), policy);
        }
        profile
    }

    #[test]
    fn parses_nft_table_json() {
        let value: Value = serde_json::from_str(
            r#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"netscope_game"}}]}"#,
        )
        .unwrap();
        assert_eq!(parse_table_names(&value), vec!["netscope_game"]);
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
    fn rules_expand_for_cgroup_and_mark() {
        let selectors = vec!["cgroup".to_string(), "mark".to_string()];
        let rules = vec!["counter drop".to_string()];
        assert_eq!(
            expand(&selectors, &rules),
            vec!["    cgroup counter drop", "    mark counter drop"]
        );
    }

    #[test]
    fn filter_allows_fall_through_to_route() {
        let manager = NftManager::new(Path::new("/sys/fs/cgroup/netscope")).unwrap();
        let profile = profile(vec![
            (
                "dropship",
                Policy::Filter {
                    default: FilterDefault::Drop,
                    exceptions: vec!["34.0.0.0/8".to_string()],
                },
            ),
            (
                "exitlink",
                Policy::Route {
                    interface: "tun0".to_string(),
                    gateway: None,
                    gateway6: None,
                    include_lan: false,
                    allow_ipv6: false,
                    udp_only: false,
                    except_ports: Vec::new(),
                    except: Vec::new(),
                },
            ),
        ]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        assert!(body.contains("ip daddr != { 127.0.0.0/8, 34.0.0.0/8 } counter drop"));
        assert!(body.contains("meta nfproto != { ipv4, ipv6 } counter drop"));
        assert!(!body.contains("34.0.0.0/8 accept"));
        assert!(body.contains("meta mark set 0x4e53"));
    }

    #[test]
    fn udp_route_marks_only_udp_and_excepts_ports() {
        let manager = NftManager::new(Path::new("/sys/fs/cgroup/netscope")).unwrap();
        let profile = profile(vec![(
            "exitlink",
            Policy::Route {
                interface: "tun0".to_string(),
                gateway: None,
                gateway6: None,
                include_lan: false,
                allow_ipv6: false,
                udp_only: true,
                except_ports: vec![53, 1900],
                except: Vec::new(),
            },
        )]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        assert!(body.contains("meta l4proto udp udp dport { 53, 1900 } accept"));
        assert!(body.contains("meta nfproto ipv4 meta l4proto udp counter meta mark set 0x4e53"));
        assert!(
            !body
                .lines()
                .any(|line| line.contains("counter meta mark set")
                    && !line.contains("meta l4proto udp")),
            "the UDP selector must be part of the mark rule"
        );
    }

    #[test]
    fn filter_runs_before_route_and_drop_is_terminal() {
        let manager = NftManager::new(Path::new("/sys/fs/cgroup/netscope")).unwrap();
        let profile = profile(vec![
            (
                "dropship",
                Policy::Filter {
                    default: FilterDefault::Allow,
                    exceptions: vec!["34.0.0.0/8".to_string()],
                },
            ),
            (
                "exitlink",
                Policy::Route {
                    interface: "tun0".to_string(),
                    gateway: None,
                    gateway6: None,
                    include_lan: false,
                    allow_ipv6: false,
                    udp_only: false,
                    except_ports: Vec::new(),
                    except: Vec::new(),
                },
            ),
        ]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        let drop_at = body.find("34.0.0.0/8").unwrap();
        let mark_at = body.find("meta mark set 0x4e53").unwrap();
        assert!(drop_at < mark_at, "filter must precede route: {body}");
        assert!(body.contains("type route hook output priority mangle"));
        assert!(body.contains("socket cgroupv2 level 2 \"netscope/game\""));
        assert!(body.contains("socket mark 0x4e53"));
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
