use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use netscope_linux::protocol::{AddProfile, ProfileStatus, RequestOp, StatusData, API_VERSION};
use netscope_linux::types::{profile_id_valid, FilterDefault, ModeSpec, ProfileId, TargetSpec};
use serde_json::Value;

use crate::client::{self, ClientError};

#[derive(Debug, Default)]
pub struct AddInput {
    pub name: String,
    pub exe: Option<PathBuf>,
    pub steam: Option<u32>,
    pub filter: Option<String>,
    pub route: Option<String>,
    pub allow_cidrs: Vec<String>,
    pub deny_cidrs: Vec<String>,
    pub gateway: Option<String>,
    pub gateway6: Option<String>,
    pub include_lan: bool,
    pub allow_ipv6: bool,
    pub target_uid: u32,
}

pub struct ModeInput<'a> {
    pub filter: Option<&'a str>,
    pub route: Option<&'a str>,
    pub allow_cidrs: &'a [String],
    pub deny_cidrs: &'a [String],
    pub gateway: Option<&'a str>,
    pub gateway6: Option<&'a str>,
    pub include_lan: bool,
    pub allow_ipv6: bool,
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if profile_id_valid(name) {
        Ok(())
    } else {
        Err(format!(
            "invalid profile name '{name}': use lowercase letters, digits, and '-' (max 32)"
        ))
    }
}

pub fn build_add(input: AddInput) -> Result<AddProfile, String> {
    validate_name(&input.name)?;
    let target = match (input.exe.as_deref(), input.steam) {
        (Some(path), None) => {
            let path = std::fs::canonicalize(path)
                .map_err(|err| format!("cannot resolve --exe {}: {err}", path.display()))?;
            let path = path
                .to_str()
                .ok_or_else(|| "--exe path is not valid UTF-8".to_string())?;
            TargetSpec::Native {
                path: path.to_string(),
            }
        }
        (None, Some(app_id)) => {
            if app_id == 0 {
                return Err("--steam app id must be greater than zero".to_string());
            }
            TargetSpec::Steam { app_id }
        }
        (Some(_), Some(_)) => return Err("--exe and --steam are mutually exclusive".to_string()),
        (None, None) => return Err("one of --exe or --steam is required".to_string()),
    };
    let mode = validate_mode(ModeInput {
        filter: input.filter.as_deref(),
        route: input.route.as_deref(),
        allow_cidrs: &input.allow_cidrs,
        deny_cidrs: &input.deny_cidrs,
        gateway: input.gateway.as_deref(),
        gateway6: input.gateway6.as_deref(),
        include_lan: input.include_lan,
        allow_ipv6: input.allow_ipv6,
    })?;
    Ok(AddProfile {
        name: input.name,
        target,
        mode,
        target_uid: input.target_uid,
    })
}

pub fn validate_mode(input: ModeInput<'_>) -> Result<ModeSpec, String> {
    match (input.filter, input.route) {
        (Some(_), Some(_)) => Err("--filter and --route are mutually exclusive".to_string()),
        (None, None) => Err("exactly one of --filter or --route is required".to_string()),
        (Some(filter), None) => {
            if input.gateway.is_some()
                || input.gateway6.is_some()
                || input.include_lan
                || input.allow_ipv6
            {
                return Err(
                    "--gateway, --gateway6, --include-lan, and --allow-ipv6 are only valid with --route"
                        .to_string(),
                );
            }
            match filter {
                "drop" => {
                    if !input.deny_cidrs.is_empty() {
                        return Err("--deny-cidr is only valid with --filter allow".to_string());
                    }
                    validate_cidrs(input.allow_cidrs)?;
                    Ok(ModeSpec::Filter {
                        default: FilterDefault::Drop,
                        allow_cidrs: input.allow_cidrs.to_vec(),
                        deny_cidrs: Vec::new(),
                    })
                }
                "allow" => {
                    if !input.allow_cidrs.is_empty() {
                        return Err("--allow-cidr is only valid with --filter drop".to_string());
                    }
                    if input.deny_cidrs.is_empty() {
                        return Err(
                            "at least one --deny-cidr is required with --filter allow".to_string()
                        );
                    }
                    validate_cidrs(input.deny_cidrs)?;
                    Ok(ModeSpec::Filter {
                        default: FilterDefault::Allow,
                        allow_cidrs: Vec::new(),
                        deny_cidrs: input.deny_cidrs.to_vec(),
                    })
                }
                other => Err(format!(
                    "invalid --filter value '{other}': expected drop or allow"
                )),
            }
        }
        (None, Some(interface)) => {
            if !input.allow_cidrs.is_empty() || !input.deny_cidrs.is_empty() {
                return Err("--allow-cidr and --deny-cidr are only valid with --filter".to_string());
            }
            if interface.is_empty()
                || interface
                    .chars()
                    .any(|character| character.is_whitespace() || character == '/')
            {
                return Err("--route requires a valid interface name".to_string());
            }
            if let Some(gateway) = input.gateway {
                if !ipv4_valid(gateway) {
                    return Err(format!("invalid --gateway '{gateway}': expected IPv4"));
                }
            }
            if let Some(gateway6) = input.gateway6 {
                if !ipv6_valid(gateway6) {
                    return Err(format!("invalid --gateway6 '{gateway6}': expected IPv6"));
                }
                if !input.allow_ipv6 {
                    return Err("--gateway6 requires --allow-ipv6".to_string());
                }
            }
            Ok(ModeSpec::Route {
                interface: interface.to_string(),
                gateway: input.gateway.map(str::to_string),
                gateway6: input.gateway6.map(str::to_string),
                include_lan: input.include_lan,
                allow_ipv6: input.allow_ipv6,
            })
        }
    }
}

fn validate_cidrs(cidrs: &[String]) -> Result<(), String> {
    for cidr in cidrs {
        if !cidr_valid(cidr) {
            return Err(format!("invalid CIDR '{cidr}'"));
        }
    }
    Ok(())
}

fn cidr_valid(cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

fn ipv4_valid(value: &str) -> bool {
    value.parse::<Ipv4Addr>().is_ok()
}

fn ipv6_valid(value: &str) -> bool {
    value.parse::<Ipv6Addr>().is_ok()
}

pub fn status(socket: &Path, json: bool) -> i32 {
    match client::send(socket, RequestOp::Status) {
        Ok(Some(data)) => {
            match data.get("api_version").and_then(Value::as_u64) {
                Some(version) if version != u64::from(API_VERSION) => {
                    return fail(ClientError::Failed(format!(
                        "daemon API version {version} is not supported"
                    )))
                }
                None => {
                    return fail(ClientError::Protocol(
                        "invalid status response: missing api_version".to_string(),
                    ))
                }
                Some(_) => {}
            }
            let status: StatusData = match serde_json::from_value(data.clone()) {
                Ok(status) => status,
                Err(err) => {
                    return fail(ClientError::Protocol(format!(
                        "invalid status response: {err}"
                    )))
                }
            };
            if json {
                print_json(&data);
            } else {
                print_status(&status);
            }
            0
        }
        Ok(None) => fail(ClientError::Protocol(
            "daemon returned no status data".to_string(),
        )),
        Err(err) => fail(err),
    }
}

pub fn list(socket: &Path, json: bool) -> i32 {
    match client::send(socket, RequestOp::List) {
        Ok(Some(data)) => {
            if json {
                print_json(&data);
                return 0;
            }
            match serde_json::from_value::<Vec<ProfileStatus>>(data) {
                Ok(profiles) => {
                    print_profiles(&profiles);
                    0
                }
                Err(err) => fail(ClientError::Protocol(format!(
                    "invalid list response: {err}"
                ))),
            }
        }
        Ok(None) => fail(ClientError::Protocol(
            "daemon returned no profile list".to_string(),
        )),
        Err(err) => fail(err),
    }
}

pub fn add(socket: &Path, profile: AddProfile) -> i32 {
    let name = profile.name.clone();
    match client::send(socket, RequestOp::Add(profile)) {
        Ok(data) => {
            println!("added {name}");
            let added = data.and_then(|value| serde_json::from_value::<ProfileStatus>(value).ok());
            if added.is_some_and(|status| !status.pids.is_empty()) {
                println!("existing connections unaffected; restart the app for full coverage");
            }
            0
        }
        Err(err) => fail(err),
    }
}

pub fn remove(socket: &Path, id: ProfileId) -> i32 {
    let message = format!("removed {id}");
    simple(socket, RequestOp::Remove { name: id }, message)
}

pub fn enable(socket: &Path, id: ProfileId) -> i32 {
    let message = format!("enabled {id}");
    simple(socket, RequestOp::Enable { name: id }, message)
}

pub fn disable(socket: &Path, id: ProfileId) -> i32 {
    let message = format!("disabled {id}");
    simple(socket, RequestOp::Disable { name: id }, message)
}

pub fn refresh(socket: &Path) -> i32 {
    simple(socket, RequestOp::Refresh, "refreshed".to_string())
}

pub fn logs(lines: usize) -> i32 {
    let count = lines.to_string();
    match Command::new("journalctl")
        .args([
            "-u",
            "netscoped",
            "-n",
            count.as_str(),
            "--no-pager",
            "-o",
            "short-iso",
        ])
        .status()
    {
        Ok(status) if status.success() => 0,
        Ok(status) => {
            eprintln!("netscope: journalctl exited with {status}");
            1
        }
        Err(err) => {
            eprintln!("netscope: run journalctl: {err}");
            1
        }
    }
}

fn simple(socket: &Path, op: RequestOp, message: String) -> i32 {
    match client::send(socket, op) {
        Ok(_) => {
            println!("{message}");
            0
        }
        Err(err) => fail(err),
    }
}

fn fail(err: ClientError) -> i32 {
    eprintln!("netscope: {}", err.message());
    err.exit_code()
}

fn print_json(value: &Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(err) => eprintln!("netscope: encode JSON output: {err}"),
    }
}

fn print_status(status: &StatusData) {
    println!(
        "DAEMON  netscoped {}  pid {}  kernel {}",
        status.daemon_version, status.pid, status.kernel
    );
    println!("CGROUP  {}", status.cgroup_root);
    print_profiles(&status.profiles);
}

fn print_profiles(profiles: &[ProfileStatus]) {
    let mut name_width = "NAME".len();
    let mut mode_width = "MODE".len();
    let mut target_width = "TARGET".len();
    let mut attached_width = "ATTACHED".len();
    for profile in profiles {
        name_width = name_width.max(profile.id.len());
        mode_width = mode_width.max(profile.mode.len());
        target_width = target_width.max(profile.target.len());
        attached_width = attached_width.max(profile.attached.len());
    }
    println!(
        "{:<name_width$}  {:<mode_width$}  {:<7}  {:<target_width$}  {:<attached_width$}  PIDS",
        "NAME", "MODE", "ENABLED", "TARGET", "ATTACHED"
    );
    for profile in profiles {
        let enabled = if profile.enabled { "yes" } else { "no" };
        let pids = profile
            .pids
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{:<name_width$}  {:<mode_width$}  {:<7}  {:<target_width$}  {:<attached_width$}  {pids}",
            profile.id, profile.mode, enabled, profile.target, profile.attached
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(input: ModeInput<'_>) -> Result<ModeSpec, String> {
        validate_mode(input)
    }

    #[test]
    fn cidr_validation_rejects_bad_prefixes() {
        assert!(cidr_valid("10.0.0.0/8"));
        assert!(cidr_valid("::1/128"));
        assert!(cidr_valid("1.1.1.1/32"));
        assert!(!cidr_valid("10.0.0.0/33"));
        assert!(!cidr_valid("::1/129"));
        assert!(!cidr_valid("10.0.0.0"));
        assert!(!cidr_valid("nope/8"));
        assert!(!cidr_valid("10.0.0.0/x"));
    }

    #[test]
    fn gateway_validation_is_family_specific() {
        assert!(ipv4_valid("192.0.2.1"));
        assert!(!ipv4_valid("2001:db8::1"));
        assert!(ipv6_valid("2001:db8::1"));
        assert!(!ipv6_valid("192.0.2.1"));
    }

    #[test]
    fn filter_drop_accepts_allow_cidrs_only() {
        let allow = vec!["1.1.1.1/32".to_string()];
        let spec = mode(ModeInput {
            filter: Some("drop"),
            route: None,
            allow_cidrs: &allow,
            deny_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        })
        .expect("valid filter");
        assert!(matches!(
            spec,
            ModeSpec::Filter {
                default: FilterDefault::Drop,
                ..
            }
        ));

        let error = mode(ModeInput {
            filter: Some("drop"),
            route: None,
            allow_cidrs: &[],
            deny_cidrs: &allow,
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        })
        .expect_err("deny with drop");
        assert!(error.contains("--deny-cidr"));
    }

    #[test]
    fn filter_allow_requires_a_deny_entry() {
        let deny = vec!["203.0.113.0/24".to_string()];
        assert!(mode(ModeInput {
            filter: Some("allow"),
            route: None,
            allow_cidrs: &[],
            deny_cidrs: &deny,
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        })
        .is_ok());
        assert!(mode(ModeInput {
            filter: Some("allow"),
            route: None,
            allow_cidrs: &[],
            deny_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        })
        .is_err());
    }

    #[test]
    fn route_flags_are_scoped_to_route() {
        assert!(mode(ModeInput {
            filter: Some("drop"),
            route: None,
            allow_cidrs: &[],
            deny_cidrs: &[],
            gateway: Some("192.0.2.1"),
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
        })
        .is_err());

        let error = mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            gateway: Some("192.0.2.1"),
            gateway6: Some("2001:db8::1"),
            include_lan: false,
            allow_ipv6: false,
        })
        .expect_err("gateway6 without ipv6");
        assert!(error.contains("--allow-ipv6"));
    }

    #[test]
    fn names_match_the_shared_rule() {
        assert!(validate_name("game").is_ok());
        assert!(validate_name("game-1").is_ok());
        assert!(validate_name("Game").is_err());
        assert!(validate_name("-game").is_err());
        assert!(validate_name("").is_err());
    }
}
