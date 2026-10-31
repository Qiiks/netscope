use std::collections::BTreeMap;

use ipnet::IpNet;
use serde_json::Value;
use thiserror::Error;

use crate::command::run;
use crate::types::{Policy, Profile, ProfileId, TABLE_BASE};

#[derive(Debug, Error)]
pub enum IpError {
    #[error("ip command failed: {0}")]
    Command(String),
    #[error("mark 0x{0:x} already in use")]
    MarkInUse(u32),
    #[error("table {0} already in use")]
    TableInUse(u32),
    #[error("profile limit reached")]
    LimitReached,
    #[error("too many route exceptions (max 30)")]
    TooManyExceptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleEntry {
    mark: u32,
    table: u32,
    priority: u32,
    dst: Option<IpNet>,
}

pub fn allocate_index(profiles: &BTreeMap<ProfileId, Profile>, max: u8) -> Result<u8, IpError> {
    let used: std::collections::HashSet<u8> = profiles.values().map(|p| p.index).collect();
    (0..max)
        .find(|index| !used.contains(index))
        .ok_or(IpError::LimitReached)
}

fn route(profile: &Profile) -> Option<&Policy> {
    profile.route_policy().map(|(_, policy)| policy)
}

fn ensure_rule_for_family(
    family: i32,
    mark: u32,
    table: u32,
    priority: u32,
) -> Result<(), IpError> {
    let rules = rules(family)?;
    if let Some(existing) = rules
        .iter()
        .find(|rule| rule.mark == mark && rule.table == table && rule.dst.is_none())
    {
        if existing.priority == priority {
            return Ok(());
        }
        return Err(IpError::MarkInUse(mark));
    }
    let mark = format!("0x{mark:x}");
    let table = table.to_string();
    let priority = priority.to_string();
    let flag = if family == 6 { "-6" } else { "-4" };
    let args = [
        flag, "rule", "add", "fwmark", &mark, "table", &table, "pref", &priority,
    ];
    run("ip", &args, None).map_err(|err| IpError::Command(err.to_string()))?;
    Ok(())
}

pub fn ensure(profile: &Profile) -> Result<(), IpError> {
    let Some(Policy::Route {
        allow_ipv6, except, ..
    }) = route(profile)
    else {
        return Ok(());
    };
    if except.len() > 30 {
        return Err(IpError::TooManyExceptions);
    }
    ensure_family(profile, 4)?;
    if let Err(err) = ensure_exceptions(profile, 4) {
        let _ = remove_family(profile, 4);
        return Err(err);
    }
    if *allow_ipv6 {
        if let Err(err) = ensure_family(profile, 6) {
            let _ = remove_family(profile, 4);
            let _ = remove_family(profile, 6);
            return Err(err);
        }
        if let Err(err) = ensure_exceptions(profile, 6) {
            let _ = remove_family(profile, 4);
            let _ = remove_family(profile, 6);
            return Err(err);
        }
    }
    Ok(())
}

fn ensure_family(profile: &Profile, family: i32) -> Result<(), IpError> {
    ensure_rule_for_family(family, profile.mark, profile.table, profile.rule_priority)?;
    let flag = if family == 6 { "-6" } else { "-4" };
    let table_arg = profile.table.to_string();
    run(
        "ip",
        &[
            flag,
            "route",
            "replace",
            "blackhole",
            "default",
            "table",
            &table_arg,
            "metric",
            "1000",
        ],
        None,
    )
    .map_err(|err| IpError::Command(err.to_string()))?;

    let Some(Policy::Route {
        interface,
        gateway,
        gateway6,
        ..
    }) = route(profile)
    else {
        return Ok(());
    };
    let gateway = if family == 6 { gateway6 } else { gateway };

    let mut args = vec![flag, "route", "replace", "default"];
    if let Some(gateway) = gateway {
        args.push("via");
        args.push(gateway.as_str());
    }
    args.extend([
        "dev",
        interface.as_str(),
        "table",
        table_arg.as_str(),
        "metric",
        "100",
    ]);
    run("ip", &args, None).map_err(|err| IpError::Command(err.to_string()))?;
    Ok(())
}

// Exceptions must be evaluated before the profile's mark rule, or the mark
// rule would send the excepted destination into the tunnel first.
fn exception_priority(rule_priority: u32, offset: usize) -> u32 {
    rule_priority - 1 - offset as u32
}

/// A route exception goes to `main` before the profile's mark rule, so a
/// direct-gate pin or PASS network is not pulled into the tunnel.
fn ensure_exceptions(profile: &Profile, family: i32) -> Result<(), IpError> {
    let Some(Policy::Route { .. }) = route(profile) else {
        return Ok(());
    };
    if let Some(Policy::Route { except, .. }) = route(profile) {
        for cidr in except {
            cidr.parse::<IpNet>()
                .map_err(|_| IpError::Command(format!("invalid exception {cidr}")))?;
        }
    }
    let flag = if family == 6 { "-6" } else { "-4" };
    let mark = format!("0x{:x}", profile.mark);
    prune_exceptions(profile, family, &mark)?;
    for (offset, cidr) in exception_cidrs(profile, family).iter().enumerate() {
        let priority = exception_priority(profile.rule_priority, offset).to_string();
        if let Err(err) = run(
            "ip",
            &[
                flag, "rule", "add", "fwmark", &mark, "to", cidr, "table", "main", "pref",
                &priority,
            ],
            None,
        ) {
            // Re-applying an unchanged profile hits the existing rule.
            if !err.to_string().contains("File exists") {
                return Err(IpError::Command(err.to_string()));
            }
        }
    }
    Ok(())
}

/// Destinations that must stay on the main table before the mark rule.
///
/// Loopback is implicit: a route scope that sent `127.0.0.1` or `::1` into
/// the tunnel would break every local client-server connection.
fn exception_cidrs(profile: &Profile, family: i32) -> Vec<String> {
    let except = match route(profile) {
        Some(Policy::Route { except, .. }) => except.as_slice(),
        _ => &[],
    };
    route_exceptions(except, family)
}

pub fn route_exceptions(except: &[String], family: i32) -> Vec<String> {
    let mut cidrs = vec![if family == 6 {
        "::1/128"
    } else {
        "127.0.0.0/8"
    }
    .to_string()];
    for cidr in except {
        let Ok(net) = cidr.parse::<IpNet>() else {
            continue;
        };
        if (family == 6) == matches!(net, IpNet::V6(_)) {
            cidrs.push(cidr.clone());
        }
    }
    cidrs
}

// A policy change can leave exceptions from the previous list in place; they
// would keep sending those destinations direct.
fn prune_exceptions(profile: &Profile, family: i32, mark: &str) -> Result<(), IpError> {
    if !matches!(route(profile), Some(Policy::Route { .. })) {
        return Ok(());
    }
    let flag = if family == 6 { "-6" } else { "-4" };
    let keep: Vec<(u32, Option<IpNet>)> = exception_cidrs(profile, family)
        .iter()
        .enumerate()
        .map(|(offset, cidr)| {
            (
                exception_priority(profile.rule_priority, offset),
                cidr.parse::<IpNet>().ok(),
            )
        })
        .collect();
    for rule in rules(family)? {
        if rule.mark != profile.mark
            || rule.table != MAIN_TABLE
            || keep
                .iter()
                .any(|(priority, dst)| *priority == rule.priority && *dst == rule.dst)
        {
            continue;
        }
        let _ = run(
            "ip",
            &[
                flag,
                "rule",
                "del",
                "fwmark",
                mark,
                "table",
                "main",
                "pref",
                &rule.priority.to_string(),
            ],
            None,
        );
    }
    Ok(())
}

pub fn remove(profile: &Profile) -> Result<(), IpError> {
    let _ = remove_family(profile, 4);
    let _ = remove_family(profile, 6);
    Ok(())
}

fn remove_family(profile: &Profile, family: i32) -> Result<(), IpError> {
    let flag = if family == 6 { "-6" } else { "-4" };
    let mark = format!("0x{:x}", profile.mark);
    let table = profile.table.to_string();
    let priority = profile.rule_priority.to_string();
    let _ = run(
        "ip",
        &[
            flag, "rule", "del", "fwmark", &mark, "table", &table, "pref", &priority,
        ],
        None,
    );
    for rule in rules(family).unwrap_or_default() {
        if rule.mark == profile.mark && rule.table == MAIN_TABLE {
            let _ = run(
                "ip",
                &[
                    flag,
                    "rule",
                    "del",
                    "fwmark",
                    &mark,
                    "table",
                    "main",
                    "pref",
                    &rule.priority.to_string(),
                ],
                None,
            );
        }
    }
    let _ = run("ip", &[flag, "route", "flush", "table", &table], None);
    Ok(())
}

pub fn exists(profile: &Profile) -> Result<bool, IpError> {
    let Some(Policy::Route {
        allow_ipv6,
        interface,
        gateway,
        gateway6,
        ..
    }) = route(profile)
    else {
        return Ok(true);
    };
    let rule_ok = rules(4)?.iter().any(|rule| {
        rule.mark == profile.mark
            && rule.table == profile.table
            && rule.priority == profile.rule_priority
    });
    if !rule_ok {
        return Ok(false);
    }
    let route_ok = blackhole_default(4, profile.table)?
        && tunnel_default(4, profile.table, interface, gateway.as_deref())?;
    if !exceptions_ok(profile, 4)? {
        return Ok(false);
    }
    if *allow_ipv6 {
        return Ok(route_ok
            && rules(6)?.iter().any(|rule| {
                rule.mark == profile.mark
                    && rule.table == profile.table
                    && rule.priority == profile.rule_priority
            })
            && blackhole_default(6, profile.table)?
            && tunnel_default(6, profile.table, interface, gateway6.as_deref())?
            && exceptions_ok(profile, 6)?);
    }
    Ok(route_ok)
}

/// Canonicalizes a CIDR to its network address so stored policies compare
/// equal to what `ip` and nftables report.
pub fn normalize_cidr(text: &str) -> Result<String, String> {
    text.parse::<IpNet>()
        .map(|net| net.trunc().to_string())
        .map_err(|_| format!("invalid cidr {text}"))
}

const MAIN_TABLE: u32 = 254;

fn exceptions_ok(profile: &Profile, family: i32) -> Result<bool, IpError> {
    if !matches!(route(profile), Some(Policy::Route { .. })) {
        return Ok(true);
    }
    let rules = rules(family)?;
    for (offset, cidr) in exception_cidrs(profile, family).iter().enumerate() {
        let net: IpNet = cidr
            .parse()
            .map_err(|_| IpError::Command(format!("invalid exception {cidr}")))?;
        let priority = exception_priority(profile.rule_priority, offset);
        if !rules.iter().any(|rule| {
            rule.mark == profile.mark
                && rule.table == MAIN_TABLE
                && rule.priority == priority
                && rule.dst == Some(net)
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn table_in_use(table: u32) -> Result<bool, IpError> {
    if !(TABLE_BASE..=TABLE_BASE + 31).contains(&table) {
        return Ok(true);
    }
    let value = show_routes("-4", table)?;
    Ok(value.as_array().is_some_and(|entries| !entries.is_empty()))
}

fn rules(family: i32) -> Result<Vec<RuleEntry>, IpError> {
    let flag = if family == 6 { "-6" } else { "-4" };
    let value = show_json(flag, &["rule", "show"])?;
    Ok(parse_rules(&value))
}

fn blackhole_default(family: i32, table: u32) -> Result<bool, IpError> {
    let flag = if family == 6 { "-6" } else { "-4" };
    let value = show_routes(flag, table)?;
    Ok(value.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry.get("type").and_then(Value::as_str) == Some("blackhole")
                && entry.get("dst").and_then(Value::as_str) == Some("default")
        })
    }))
}

fn tunnel_default(
    family: i32,
    table: u32,
    interface: &str,
    gateway: Option<&str>,
) -> Result<bool, IpError> {
    let flag = if family == 6 { "-6" } else { "-4" };
    let value = show_routes(flag, table)?;
    Ok(value.as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| is_tunnel_default(entry, interface, gateway))
    }))
}

fn is_tunnel_default(entry: &Value, interface: &str, gateway: Option<&str>) -> bool {
    entry.get("dst").and_then(Value::as_str) == Some("default")
        && entry.get("type").and_then(Value::as_str) != Some("blackhole")
        && entry.get("dev").and_then(Value::as_str) == Some(interface)
        && entry.get("metric").and_then(Value::as_u64) == Some(100)
        && gateway
            .is_none_or(|expected| entry.get("gateway").and_then(Value::as_str) == Some(expected))
}

// `ip route show table N` exits 2 when the table has never been created;
// treat that as an empty table rather than a command failure.
fn show_routes(family_flag: &str, table: u32) -> Result<Value, IpError> {
    let table = table.to_string();
    let output = std::process::Command::new("ip")
        .args([family_flag, "-j", "route", "show", "table", &table])
        .output()
        .map_err(|err| IpError::Command(err.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("FIB table does not exist") {
            return Ok(Value::Array(Vec::new()));
        }
        return Err(IpError::Command(format!(
            "ip exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| IpError::Command(format!("parse ip json: {err}")))
}

fn show_json(family_flag: &str, args: &[&str]) -> Result<Value, IpError> {
    let mut full = vec![family_flag, "-j"];
    full.extend_from_slice(args);
    let output = run("ip", &full, None).map_err(|err| IpError::Command(err.to_string()))?;
    serde_json::from_slice(&output.stdout)
        .map_err(|err| IpError::Command(format!("parse ip json: {err}")))
}

fn parse_rules(value: &Value) -> Vec<RuleEntry> {
    value
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    let mark = entry
                        .get("fwmark")
                        .and_then(value_u32)
                        .or_else(|| entry.get("mark").and_then(value_u32))?;
                    let table = entry.get("table").and_then(table_u32)?;
                    let priority = entry
                        .get("priority")
                        .and_then(value_u32)
                        .or_else(|| entry.get("pref").and_then(value_u32))?;
                    Some(RuleEntry {
                        mark,
                        table,
                        priority,
                        dst: rule_dst(entry),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// `ip -j rule show` reports a network as `dst` plus a separate `dstlen`.
fn rule_dst(entry: &Value) -> Option<IpNet> {
    let text = entry.get("dst").and_then(Value::as_str)?;
    if let Ok(net) = text.parse::<IpNet>() {
        return Some(net);
    }
    let address = text.parse().ok()?;
    let len = entry
        .get("dstlen")
        .and_then(value_u32)
        .unwrap_or(match address {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        });
    let len = u8::try_from(len).ok()?;
    IpNet::new(address, len).ok()
}

fn table_u32(value: &Value) -> Option<u32> {
    match value.as_str() {
        Some("main") => Some(MAIN_TABLE),
        Some("local") => Some(255),
        Some("default") => Some(253),
        _ => value_u32(value),
    }
}

fn value_u32(value: &Value) -> Option<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).ok();
    }
    let text = value.as_str()?;
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_exceptions_always_keep_loopback() {
        let except = vec!["34.0.0.0/8".to_string(), "2001:db8::/32".to_string()];
        assert_eq!(
            route_exceptions(&except, 4),
            vec!["127.0.0.0/8", "34.0.0.0/8"]
        );
        assert_eq!(
            route_exceptions(&except, 6),
            vec!["::1/128", "2001:db8::/32"]
        );
    }

    #[test]
    fn parses_rule_json_strings() {
        let value: Value =
            serde_json::from_str(r#"[{"priority":1000,"fwmark":"0x4e53","table":"20000"}]"#)
                .unwrap();
        assert_eq!(
            parse_rules(&value),
            vec![RuleEntry {
                mark: 0x4e53,
                table: 20000,
                priority: 1000,
                dst: None
            }]
        );
    }

    #[test]
    fn cidr_normalization_masks_host_bits() {
        assert_eq!(normalize_cidr("1.1.1.1/24").unwrap(), "1.1.1.0/24");
        assert_eq!(normalize_cidr("2001:db8::1/32").unwrap(), "2001:db8::/32");
        assert!(normalize_cidr("1.1.1.1/33").is_err());
        assert!(normalize_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn tunnel_default_matches_route_and_rejects_blackhole() {
        let route: Value = serde_json::from_str(
            r#"{"dst":"default","type":"unicast","dev":"tun0","metric":100,"gateway":"10.0.0.1"}"#,
        )
        .unwrap();
        assert!(is_tunnel_default(&route, "tun0", Some("10.0.0.1")));
        assert!(!is_tunnel_default(&route, "tun1", Some("10.0.0.1")));
        assert!(!is_tunnel_default(&route, "tun0", Some("10.0.0.2")));
        let blackhole: Value = serde_json::from_str(
            r#"{"dst":"default","type":"blackhole","dev":"tun0","metric":100}"#,
        )
        .unwrap();
        assert!(!is_tunnel_default(&blackhole, "tun0", None));
    }

    #[test]
    fn parses_named_table_in_exception_rule() {
        let value: Value = serde_json::from_str(
            r#"[{"priority":999,"dst":"34.0.0.0","dstlen":8,"fwmark":"0x4e53","table":"main"}]"#,
        )
        .unwrap();
        assert_eq!(
            parse_rules(&value),
            vec![RuleEntry {
                mark: 0x4e53,
                table: MAIN_TABLE,
                priority: 999,
                dst: Some("34.0.0.0/8".parse().unwrap())
            }]
        );
    }

    #[test]
    fn exception_rules_precede_the_mark_rule() {
        assert_eq!(exception_priority(1000, 0), 999);
        assert_eq!(exception_priority(1032, 0), 1031);
        assert_eq!(exception_priority(1032, 29), 1002);
        for index in 0..32 {
            assert!(exception_priority(1000 + 32 * index, 29) > 0);
            assert!(exception_priority(1000 + 32 * index, 0) < 1000 + 32 * index);
        }
    }

    #[test]
    fn table_range_is_closed() {
        assert!(table_in_use(19999).unwrap());
        assert!(table_in_use(20032).unwrap());
    }
}
