use std::fs;
use std::path::Path;

use netscope_linux::cgroup::CgroupManager;
use netscope_linux::nft::NftManager;
use netscope_linux::protocol::RequestOp;
use netscope_linux::types::{profile_id_valid, Config, TABLE_BASE};
use netscope_linux::{run as run_command, run_output as run_command_output};
use serde_json::Value;

use crate::client;

const NFT_ROOT: &str = "/sys/fs/cgroup/netscope";

pub fn run(socket: Option<&Path>, all: bool, purge: bool) -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("netscope: cleanup requires root: sudo netscope cleanup --all");
        return 4;
    }
    if !all {
        eprintln!("netscope: cleanup requires --all");
        return 2;
    }

    let config = client::load_config();
    let socket = socket
        .map(Path::to_path_buf)
        .unwrap_or_else(|| config.daemon.socket_path.clone());
    match client::send(&socket, RequestOp::Status) {
        Err(client::ClientError::Unavailable(_)) => {}
        _ => {
            eprintln!("cleanup requires the daemon stopped: sudo systemctl stop netscoped");
            return 3;
        }
    }

    let mut ok = true;
    ok &= clean_nft();
    ok &= clean_ip();
    ok &= clean_cgroups(&config.daemon.cgroup_root);
    if purge {
        ok &= purge_files(&config);
    }

    if ok {
        println!("cleanup complete");
        0
    } else {
        eprintln!("netscope: cleanup completed with errors");
        1
    }
}

fn clean_nft() -> bool {
    let manager = match NftManager::new(Path::new(NFT_ROOT)) {
        Ok(manager) => manager,
        Err(err) => {
            eprintln!("netscope: nft setup: {err}");
            return false;
        }
    };
    let tables = match manager.list_tables() {
        Ok(tables) => tables,
        Err(err) => {
            eprintln!("netscope: list nft tables: {err}");
            return false;
        }
    };
    let mut ok = true;
    for name in tables.iter().filter(|name| name.starts_with("netscope_")) {
        if let Err(err) = run_command("nft", &["delete", "table", "inet", name.as_str()], None) {
            eprintln!("netscope: delete nft table {name}: {err:#}");
            ok = false;
        }
    }
    ok
}

fn clean_ip() -> bool {
    let mut ok = true;
    for flag in ["-4", "-6"] {
        match run_command_output("ip", &[flag, "-j", "rule", "show"]) {
            Ok(output) => match serde_json::from_str::<Value>(&output) {
                Ok(value) => {
                    for rule in value.as_array().into_iter().flatten() {
                        if let Err(err) = delete_rule(flag, rule) {
                            eprintln!("netscope: delete ip rule: {err:#}");
                            ok = false;
                        }
                    }
                }
                Err(err) => {
                    eprintln!("netscope: parse ip rules: {err}");
                    ok = false;
                }
            },
            Err(err) => {
                eprintln!("netscope: list ip rules: {err:#}");
                ok = false;
            }
        }
        for table in TABLE_BASE..=TABLE_BASE + 31 {
            let table = table.to_string();
            if let Err(err) = run_command("ip", &[flag, "route", "flush", "table", &table], None) {
                eprintln!("netscope: flush ip route table {table}: {err:#}");
                ok = false;
            }
        }
    }
    ok
}

fn delete_rule(flag: &str, rule: &Value) -> anyhow::Result<()> {
    let Some(table) = rule.get("table").and_then(value_u32) else {
        return Ok(());
    };
    if !(TABLE_BASE..=TABLE_BASE + 31).contains(&table) {
        return Ok(());
    }
    let table = table.to_string();
    let mut args = vec![flag, "rule", "del", "table", &table];
    let priority = rule
        .get("priority")
        .or_else(|| rule.get("pref"))
        .and_then(value_u32)
        .map(|priority| priority.to_string());
    if let Some(priority) = &priority {
        args.push("pref");
        args.push(priority);
    }
    run_command("ip", &args, None)?;
    Ok(())
}

fn clean_cgroups(root: &Path) -> bool {
    let manager = match CgroupManager::new(root.to_path_buf()) {
        Ok(manager) => manager,
        Err(err) => {
            eprintln!("netscope: cgroup setup: {err}");
            return false;
        }
    };
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return true,
        Err(err) => {
            eprintln!("netscope: list cgroups: {err}");
            return false;
        }
    };
    let mut ok = true;
    for entry in entries.flatten() {
        let is_directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if !is_directory {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !profile_id_valid(&name) {
            continue;
        }
        if let Err(err) = manager.remove(&name) {
            eprintln!("netscope: remove cgroup {name}: {err}");
            ok = false;
        }
    }
    ok
}

fn purge_files(config: &Config) -> bool {
    let mut ok = true;
    for path in [
        config.daemon.state_path.clone(),
        std::path::PathBuf::from(client::CONFIG_PATH),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                eprintln!("netscope: remove {}: {err}", path.display());
                ok = false;
            }
        }
    }
    ok
}

fn value_u32(value: &Value) -> Option<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).ok();
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
    fn ip_json_scalars_normalize() {
        assert_eq!(value_u32(&Value::from(20000u64)), Some(20000));
        assert_eq!(value_u32(&Value::from("20000")), Some(20000));
        assert_eq!(value_u32(&Value::from("0x4e53")), Some(20051));
        assert_eq!(value_u32(&Value::from("0X4E53")), Some(20051));
        assert_eq!(value_u32(&Value::from("nope")), None);
        assert_eq!(value_u32(&Value::Bool(true)), None);
    }
}
