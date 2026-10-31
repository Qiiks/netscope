use std::collections::BTreeMap;

use serde_json::Value;
use thiserror::Error;

use crate::command::run;
use crate::types::{Profile, ProfileId, TABLE_BASE};

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleEntry {
    mark: u32,
    table: u32,
    priority: u32,
}

pub fn allocate_index(profiles: &BTreeMap<ProfileId, Profile>, max: u8) -> Result<u8, IpError> {
    let used: std::collections::HashSet<u8> = profiles.values().map(|p| p.index).collect();
    (0..max)
        .find(|index| !used.contains(index))
        .ok_or(IpError::LimitReached)
}

fn ensure_rule_for_family(
    family: i32,
    mark: u32,
    table: u32,
    priority: u32,
) -> Result<(), IpError> {
    let rules = rules(family)?;
    if let Some(existing) = rules.iter().find(|rule| rule.mark == mark) {
        if existing.table == table && existing.priority == priority {
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
    if !matches!(profile.mode, crate::types::Mode::Route { .. }) {
        return Ok(());
    }
    ensure_family(profile, 4)?;
    if matches!(
        profile.mode,
        crate::types::Mode::Route {
            allow_ipv6: true,
            ..
        }
    ) {
        if let Err(err) = ensure_family(profile, 6) {
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

    let (interface, gateway) = match &profile.mode {
        crate::types::Mode::Route {
            interface,
            gateway,
            gateway6,
            ..
        } => (interface, if family == 6 { gateway6 } else { gateway }),
        _ => return Ok(()),
    };

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

pub fn remove(profile: &Profile) -> Result<(), IpError> {
    let _ = remove_family(profile, 4);
    if matches!(
        profile.mode,
        crate::types::Mode::Route {
            allow_ipv6: true,
            ..
        }
    ) {
        let _ = remove_family(profile, 6);
    }
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
    let _ = run("ip", &[flag, "route", "flush", "table", &table], None);
    Ok(())
}

pub fn exists(profile: &Profile) -> Result<bool, IpError> {
    if !matches!(profile.mode, crate::types::Mode::Route { .. }) {
        return Ok(true);
    }
    let rule_ok = rules(4)?.iter().any(|rule| {
        rule.mark == profile.mark
            && rule.table == profile.table
            && rule.priority == profile.rule_priority
    });
    if !rule_ok {
        return Ok(false);
    }
    let route_ok = blackhole_default(4, profile.table)?;
    if matches!(
        profile.mode,
        crate::types::Mode::Route {
            allow_ipv6: true,
            ..
        }
    ) {
        return Ok(route_ok
            && rules(6)?.iter().any(|rule| {
                rule.mark == profile.mark
                    && rule.table == profile.table
                    && rule.priority == profile.rule_priority
            })
            && blackhole_default(6, profile.table)?);
    }
    Ok(route_ok)
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
                    let table = entry.get("table").and_then(value_u32)?;
                    let priority = entry
                        .get("priority")
                        .and_then(value_u32)
                        .or_else(|| entry.get("pref").and_then(value_u32))?;
                    Some(RuleEntry {
                        mark,
                        table,
                        priority,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
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
    fn parses_rule_json_strings() {
        let value: Value =
            serde_json::from_str(r#"[{"priority":1000,"fwmark":"0x4e53","table":"20000"}]"#)
                .unwrap();
        assert_eq!(
            parse_rules(&value),
            vec![RuleEntry {
                mark: 0x4e53,
                table: 20000,
                priority: 1000
            }]
        );
    }

    #[test]
    fn table_range_is_closed() {
        assert!(table_in_use(19999).unwrap());
        assert!(table_in_use(20032).unwrap());
    }
}
