use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
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

const NAMED_COUNTERS: [&str; 6] = ["seen_cg", "seen_mk", "rx_cg", "rx_mk", "routed", "dropped"];

/// Cumulative bytes and packets for one profile table, summed over both
/// selectors. `routed` is not exposed: `ProfileStats` reports only traffic,
/// packets, and drops.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Bytes sent by the profile, summed over `seen_cg` and `seen_mk`.
    pub tx_bytes: u64,
    /// Packets sent by the profile, summed over both selectors.
    pub tx_packets: u64,
    /// Bytes received by the profile, summed over `rx_cg` and `rx_mk`.
    pub rx_bytes: u64,
    /// Packets received by the profile, summed over both selectors.
    pub rx_packets: u64,
    /// Bytes matched by a drop rule.
    pub dropped_bytes: u64,
    /// Packets matched by a drop rule.
    pub dropped_packets: u64,
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

    /// Applies the profile's ruleset and reports whether the table was
    /// recreated (and its counters therefore reset).
    ///
    /// A missing table, missing named counters (the pre-0.3.0 upgrade), or a
    /// hook change needs a recreate. Otherwise one transaction flushes the
    /// four chains and re-adds their rules, which preserves the named counters.
    ///
    /// # Errors
    ///
    /// Returns [`NftError::Command`] when nft cannot read or write the table.
    pub fn apply(&self, profile: &Profile) -> Result<bool, NftError> {
        if !profile.has_policies() {
            self.remove(profile)?;
            return Ok(false);
        }
        let name = Self::table_name(profile);
        let selectors = self.profile_selectors(profile);
        let body = Self::render_body(profile, &selectors)?;
        let state = table_state(&name)?;
        let kind = if profile.has_route() {
            "route"
        } else {
            "filter"
        };
        let (recreate, script) = render_script(&name, &body, &state, kind);
        run("nft", &["-f", "-"], Some(script.as_bytes()))?;
        Ok(recreate)
    }

    /// Reads every profile table's named counters with one `nft -j list
    /// ruleset`, keyed by table name.
    ///
    /// # Errors
    ///
    /// Returns [`NftError::Command`] when nft fails or its JSON cannot be
    /// parsed.
    pub fn counters(&self) -> Result<HashMap<String, CounterSnapshot>, NftError> {
        Ok(parse_counters(&read_ruleset()?))
    }

    pub fn remove(&self, profile: &Profile) -> Result<(), NftError> {
        if !self.exists(profile)? {
            return Ok(());
        }
        let name = Self::table_name(profile);
        run("nft", &["delete", "table", "inet", &name], None)?;
        Ok(())
    }

    fn render_body(profile: &Profile, selectors: &[String; 2]) -> Result<String, NftError> {
        let rules = render_rules(profile)?;
        // A route chain reroutes after the mark is set; a filter chain does
        // not, so cgroup-marked packets would keep their original route.
        let (kind, priority) = if profile.has_route() {
            ("route", "mangle")
        } else {
            ("filter", "filter")
        };
        Ok(render_table(kind, priority, selectors, &rules))
    }
}

fn render_rules(profile: &Profile) -> Result<Vec<String>, NftError> {
    let mut rules = Vec::new();
    render_filter_rules(profile, &mut rules)?;
    render_route_rules(profile, &mut rules);
    Ok(rules)
}

fn render_filter_rules(profile: &Profile, rules: &mut Vec<String>) -> Result<(), NftError> {
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
                        rules.push("meta nfproto ipv4 counter name dropped drop".to_string());
                    } else {
                        rules.push(format!(
                            "meta nfproto ipv4 ip daddr != {{ {} }} counter name dropped drop",
                            v4.join(", ")
                        ));
                    }
                    if v6.is_empty() {
                        rules.push("meta nfproto ipv6 counter name dropped drop".to_string());
                    } else {
                        rules.push(format!(
                            "meta nfproto ipv6 ip6 daddr != {{ {} }} counter name dropped drop",
                            v6.join(", ")
                        ));
                    }
                    rules.push(
                        "meta nfproto != { ipv4, ipv6 } counter name dropped drop".to_string(),
                    );
                }
                FilterDefault::Allow => {
                    for exception in exceptions {
                        rules.push(format!(
                            "{} counter name dropped drop",
                            render_address(exception)?
                        ));
                    }
                }
            },
            Policy::Route { .. } => unreachable!("filter_policies only yields filters"),
        }
    }
    Ok(())
}

fn render_route_rules(profile: &Profile, rules: &mut Vec<String>) {
    let Some((
        _,
        Policy::Route {
            interface: _,
            gateway: _,
            gateway6: _,
            include_lan,
            allow_ipv6,
            udp_only,
            except_ports,
            except_sports,
            ..
        },
    )) = profile.route_policy()
    else {
        return;
    };
    rules.push("meta nfproto ipv4 ip daddr 127.0.0.0/8 accept".to_string());
    rules.push("meta nfproto ipv6 ip6 daddr ::1/128 accept".to_string());
    if !include_lan {
        rules.push("meta nfproto ipv4 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 } accept".to_string());
        rules.push(
            "meta nfproto ipv6 ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } accept".to_string(),
        );
    }
    if !allow_ipv6 {
        rules.push("meta nfproto ipv6 counter name dropped drop".to_string());
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
        if !except_sports.is_empty() {
            let sports = except_sports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            rules.push(format!(
                "meta nfproto ipv4 meta l4proto udp udp sport {{ {sports} }} accept"
            ));
        }
        "meta nfproto ipv4 meta l4proto udp "
    } else {
        ""
    };
    rules.push(format!(
        "{selector}counter name routed meta mark set 0x{:x}",
        profile.mark
    ));
}

fn render_table(kind: &str, priority: &str, selectors: &[String; 2], rules: &[String]) -> String {
    let mut body = String::new();
    for counter in NAMED_COUNTERS {
        writeln!(body, "  counter {counter} {{ }}").expect("writing to a String cannot fail");
    }
    writeln!(
        body,
        "  chain output {{\n    type {kind} hook output priority {priority}; policy accept;"
    )
    .expect("writing to a String cannot fail");
    for (selector, counter) in selectors.iter().zip(["seen_cg", "seen_mk"]) {
        writeln!(body, "    {selector} counter name {counter} goto dispatch")
            .expect("writing to a String cannot fail");
    }
    body.push_str("  }\n  chain dispatch {\n");
    for rule in rules {
        writeln!(body, "    {rule}").expect("writing to a String cannot fail");
    }
    body.push_str(
        "  }\n  chain input {\n    type filter hook input priority filter; policy accept;\n",
    );
    for (selector, counter) in selectors.iter().zip(["rx_cg", "rx_mk"]) {
        writeln!(body, "    {selector} counter name {counter} goto rx_sink")
            .expect("writing to a String cannot fail");
    }
    body.push_str("  }\n  chain rx_sink {\n  }\n");
    body
}

fn table_state(name: &str) -> Result<TableState, NftError> {
    Ok(parse_table_state(&read_ruleset()?, name))
}

fn read_ruleset() -> Result<Value, NftError> {
    let output = run("nft", &["-j", "list", "ruleset"], None)?;
    serde_json::from_slice(&output.stdout)
        .map_err(|err| NftError::Command(anyhow::anyhow!("parse nft ruleset: {err}")))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TableState {
    exists: bool,
    output_type: Option<String>,
    counters: HashSet<String>,
}

fn render_script(name: &str, body: &str, state: &TableState, kind: &str) -> (bool, String) {
    let recreate = !state.exists
        || state.output_type.as_deref() != Some(kind)
        || !NAMED_COUNTERS
            .iter()
            .all(|counter| state.counters.contains(*counter));
    if recreate {
        let change = if state.exists { "delete" } else { "add" };
        return (
            true,
            format!("{change} table inet {name}\ntable inet {name} {{\n{body}}}\n"),
        );
    }
    (
        false,
        format!(
            "flush chain inet {name} output\n\
             flush chain inet {name} dispatch\n\
             flush chain inet {name} input\n\
             flush chain inet {name} rx_sink\n\
             table inet {name} {{\n{body}}}\n"
        ),
    )
}

fn parse_table_state(value: &Value, name: &str) -> TableState {
    let mut state = TableState::default();
    let Some(entries) = value.get("nftables").and_then(Value::as_array) else {
        return state;
    };
    for entry in entries {
        if let Some(table) = entry.get("table") {
            if table.get("family").and_then(Value::as_str) == Some("inet")
                && table.get("name").and_then(Value::as_str) == Some(name)
            {
                state.exists = true;
            }
        }
        if let Some(chain) = entry.get("chain") {
            if chain.get("table").and_then(Value::as_str) == Some(name)
                && chain.get("name").and_then(Value::as_str) == Some("output")
            {
                state.output_type = chain
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
        if let Some(counter) = entry.get("counter") {
            if counter.get("table").and_then(Value::as_str) == Some(name) {
                if let Some(counter_name) = counter.get("name").and_then(Value::as_str) {
                    state.counters.insert(counter_name.to_string());
                }
            }
        }
    }
    state
}

fn parse_counters(value: &Value) -> HashMap<String, CounterSnapshot> {
    let mut counters: HashMap<String, CounterSnapshot> = HashMap::new();
    let Some(entries) = value.get("nftables").and_then(Value::as_array) else {
        return counters;
    };
    for entry in entries {
        let Some(counter) = entry.get("counter") else {
            continue;
        };
        let (Some(table), Some(name)) = (
            counter.get("table").and_then(Value::as_str),
            counter.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        let bytes = counter.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        let packets = counter.get("packets").and_then(Value::as_u64).unwrap_or(0);
        let snapshot = counters.entry(table.to_string()).or_default();
        match name {
            "seen_cg" | "seen_mk" => {
                snapshot.tx_bytes = snapshot.tx_bytes.saturating_add(bytes);
                snapshot.tx_packets = snapshot.tx_packets.saturating_add(packets);
            }
            "rx_cg" | "rx_mk" => {
                snapshot.rx_bytes = snapshot.rx_bytes.saturating_add(bytes);
                snapshot.rx_packets = snapshot.rx_packets.saturating_add(packets);
            }
            "dropped" => {
                snapshot.dropped_bytes = snapshot.dropped_bytes.saturating_add(bytes);
                snapshot.dropped_packets = snapshot.dropped_packets.saturating_add(packets);
            }
            _ => {}
        }
    }
    counters
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
    fn renderer_names_counters_and_emits_dispatch_once() {
        let manager = NftManager::new(Path::new("/sys/fs/cgroup/netscope")).unwrap();
        let profile = profile(vec![(
            "exitlink",
            Policy::Route {
                interface: "tun0".to_string(),
                gateway: None,
                gateway6: None,
                links: Vec::new(),
                include_lan: false,
                allow_ipv6: false,
                udp_only: false,
                except_ports: Vec::new(),
                except_sports: Vec::new(),
                except: Vec::new(),
            },
        )]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        for counter in NAMED_COUNTERS {
            assert!(
                body.contains(&format!("counter {counter} {{ }}")),
                "missing {counter}: {body}"
            );
        }
        assert_eq!(body.matches("goto dispatch").count(), 2, "{body}");
        assert_eq!(body.matches("goto rx_sink").count(), 2, "{body}");
        assert_eq!(
            body.matches("meta mark set 0x4e53").count(),
            1,
            "dispatch body must be emitted once: {body}"
        );
        assert!(body.contains("counter name seen_cg goto dispatch"));
        assert!(body.contains("counter name seen_mk goto dispatch"));
        assert!(body.contains("counter name rx_cg goto rx_sink"));
        assert!(body.contains("counter name rx_mk goto rx_sink"));
        assert!(
            !body.lines().any(|line| line.ends_with("counter drop")),
            "anonymous counter: {body}"
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
                    links: Vec::new(),
                    include_lan: false,
                    allow_ipv6: false,
                    udp_only: false,
                    except_ports: Vec::new(),
                    except_sports: Vec::new(),
                    except: Vec::new(),
                },
            ),
        ]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        assert!(body.contains("ip daddr != { 127.0.0.0/8, 34.0.0.0/8 } counter name dropped drop"));
        assert!(body.contains("meta nfproto != { ipv4, ipv6 } counter name dropped drop"));
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
                links: Vec::new(),
                include_lan: false,
                allow_ipv6: false,
                udp_only: true,
                except_ports: vec![53, 1900],
                except_sports: Vec::new(),
                except: Vec::new(),
            },
        )]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        assert!(body.contains("meta l4proto udp udp dport { 53, 1900 } accept"));
        assert!(body.contains(
            "meta nfproto ipv4 meta l4proto udp counter name routed meta mark set 0x4e53"
        ));
        assert!(
            !body
                .lines()
                .any(|line| line.contains("counter name routed meta mark set")
                    && !line.contains("meta l4proto udp")),
            "the UDP selector must be part of the mark rule"
        );
    }

    #[test]
    fn a_udp_route_pins_existing_source_ports_before_the_mark() {
        let manager = NftManager::new(Path::new("/sys/fs/cgroup/netscope")).unwrap();
        let profile = profile(vec![(
            "exitlink",
            Policy::Route {
                interface: "tun0".to_string(),
                gateway: None,
                gateway6: None,
                links: Vec::new(),
                include_lan: false,
                allow_ipv6: false,
                udp_only: true,
                except_ports: Vec::new(),
                except_sports: vec![52665, 49227],
                except: Vec::new(),
            },
        )]);
        let body = NftManager::render_body(&profile, &manager.profile_selectors(&profile)).unwrap();
        let sport_rule = body
            .lines()
            .position(|line| line.contains("udp sport { 52665, 49227 } accept"))
            .expect("existing source ports stay direct");
        let mark_rule = body
            .lines()
            .position(|line| line.contains("counter name routed meta mark set 0x4e53"))
            .expect("other flows are marked");
        assert!(
            sport_rule < mark_rule,
            "the pin must run before the mark, or the live flow is rerouted"
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
                    links: Vec::new(),
                    include_lan: false,
                    allow_ipv6: false,
                    udp_only: false,
                    except_ports: Vec::new(),
                    except_sports: Vec::new(),
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

    // Captured from `nft -j list ruleset` on nft 1.1.7.
    const NFT_FIXTURE: &str = r#"{"nftables":[{"metainfo":{"version":"1.1.7","release_name":"Commodore Bullmoose #8","json_schema_version":1}},{"table":{"family":"inet","name":"ns_fixture","handle":30}},{"chain":{"family":"inet","table":"ns_fixture","name":"output","handle":1,"type":"filter","hook":"output","prio":0,"policy":"accept"}},{"chain":{"family":"inet","table":"ns_fixture","name":"dispatch","handle":2}},{"counter":{"family":"inet","name":"seen_cg","table":"ns_fixture","handle":3,"packets":6,"bytes":802}},{"counter":{"family":"inet","name":"routed","table":"ns_fixture","handle":4,"packets":0,"bytes":0}},{"rule":{"family":"inet","table":"ns_fixture","chain":"output","handle":5,"expr":[{"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":1000}},{"counter":"seen_cg"},{"goto":{"target":"dispatch"}}]}},{"rule":{"family":"inet","table":"ns_fixture","chain":"dispatch","handle":6,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"203.0.113.0","len":24}}}},{"counter":"routed"},{"drop":null}]}}]}"#;

    #[test]
    fn parses_named_counters_from_a_real_ruleset() {
        let value: Value = serde_json::from_str(NFT_FIXTURE).unwrap();
        let counters = parse_counters(&value);
        assert_eq!(
            counters.get("ns_fixture"),
            Some(&CounterSnapshot {
                tx_bytes: 802,
                tx_packets: 6,
                ..Default::default()
            })
        );
    }

    #[test]
    fn counter_parser_sums_both_selectors_and_drops() {
        let value: Value = serde_json::from_str(
            r#"{"nftables":[
                {"counter":{"family":"inet","table":"t","name":"seen_cg","packets":2,"bytes":20}},
                {"counter":{"family":"inet","table":"t","name":"seen_mk","packets":3,"bytes":30}},
                {"counter":{"family":"inet","table":"t","name":"rx_cg","packets":4,"bytes":40}},
                {"counter":{"family":"inet","table":"t","name":"rx_mk","packets":5,"bytes":50}},
                {"counter":{"family":"inet","table":"t","name":"routed","packets":6,"bytes":60}},
                {"counter":{"family":"inet","table":"t","name":"dropped","packets":1,"bytes":10}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            parse_counters(&value).get("t"),
            Some(&CounterSnapshot {
                tx_bytes: 50,
                tx_packets: 5,
                rx_bytes: 90,
                rx_packets: 9,
                dropped_bytes: 10,
                dropped_packets: 1,
            })
        );
    }

    fn complete_state(kind: &str) -> TableState {
        TableState {
            exists: true,
            output_type: Some(kind.to_string()),
            counters: NAMED_COUNTERS.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn apply_plan_recreates_only_when_the_table_counters_or_hook_differ() {
        let complete = complete_state("route");
        assert!(
            !render_script("t", "body", &complete, "route").0,
            "complete table is flushed, not recreated"
        );
        assert!(render_script("t", "body", &TableState::default(), "route").0);
        assert!(
            render_script("t", "body", &complete_state("filter"), "route").0,
            "a hook change needs a recreate"
        );
        let mut missing = complete_state("route");
        missing.counters.remove("dropped");
        assert!(render_script("t", "body", &missing, "route").0);
    }

    #[test]
    fn flush_script_keeps_counters_and_recreate_swaps_the_table() {
        let (recreate, flush) = render_script(
            "netscope_game",
            "  chain output {\n  }",
            &complete_state("route"),
            "route",
        );
        assert!(!recreate);
        for chain in ["output", "dispatch", "input", "rx_sink"] {
            assert!(
                flush.contains(&format!("flush chain inet netscope_game {chain}")),
                "{flush}"
            );
        }
        assert!(!flush.contains("delete table"));
        assert!(!flush.contains("add counter"));
        assert_eq!(flush.matches("chain output").count(), 1);

        let (recreate, create) =
            render_script("netscope_game", "body", &TableState::default(), "route");
        assert!(recreate);
        assert!(create.starts_with("add table inet netscope_game"));

        let mut old = TableState {
            exists: true,
            ..Default::default()
        };
        old.output_type = Some("filter".to_string());
        let (recreate, replace) = render_script("netscope_game", "body", &old, "route");
        assert!(recreate);
        assert!(replace.starts_with("delete table inet netscope_game"));
    }

    #[test]
    fn fixture_without_named_counters_is_an_upgrade_recreate() {
        let value: Value = serde_json::from_str(NFT_FIXTURE).unwrap();
        let state = parse_table_state(&value, "ns_fixture");
        assert!(state.exists);
        assert_eq!(state.output_type.as_deref(), Some("filter"));
        assert!(state.counters.contains("seen_cg"));
        assert!(render_script("ns_fixture", "body", &state, "filter").0);
    }
}
