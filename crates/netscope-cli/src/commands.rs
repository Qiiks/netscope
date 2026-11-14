use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use netscope_linux::protocol::{
    AddProfile, CloseResult, OpenScope, ProfileStatus, RequestOp, ScopeHandle, StatusData,
    API_VERSION,
};
use netscope_linux::types::{
    profile_id_valid, FilterDefault, ModeSpec, ProfileId, RouteLink, TargetSpec,
};
use serde_json::Value;

use crate::client::{self, ClientError};

#[derive(Debug, Default)]
pub struct AddInput {
    pub name: String,
    pub exe: Option<PathBuf>,
    pub wine: Option<PathBuf>,
    pub process: Option<String>,
    pub steam: Option<u32>,
    pub filter: Option<String>,
    pub route: Option<String>,
    pub links: Vec<String>,
    pub allow_cidrs: Vec<String>,
    pub deny_cidrs: Vec<String>,
    pub except_cidrs: Vec<String>,
    pub gateway: Option<String>,
    pub gateway6: Option<String>,
    pub include_lan: bool,
    pub allow_ipv6: bool,
    pub udp_only: bool,
    pub except_ports: Vec<u16>,
    pub except_sports: Vec<u16>,
    pub target_uid: u32,
}

pub struct ModeInput<'a> {
    pub filter: Option<&'a str>,
    pub route: Option<&'a str>,
    pub allow_cidrs: &'a [String],
    pub deny_cidrs: &'a [String],
    pub except_cidrs: &'a [String],
    pub gateway: Option<&'a str>,
    pub gateway6: Option<&'a str>,
    pub include_lan: bool,
    pub allow_ipv6: bool,
    pub udp_only: bool,
    pub except_ports: &'a [u16],
    pub except_sports: &'a [u16],
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

pub fn build_target(input: &AddInput) -> Result<TargetSpec, String> {
    match (
        input.exe.as_deref(),
        input.wine.as_deref(),
        input.process.as_deref(),
        input.steam,
    ) {
        (Some(path), None, None, None) => {
            let path = std::fs::canonicalize(path)
                .map_err(|err| format!("cannot resolve --exe {}: {err}", path.display()))?;
            let path = path
                .to_str()
                .ok_or_else(|| "--exe path is not valid UTF-8".to_string())?;
            Ok(TargetSpec::Native {
                path: path.to_string(),
            })
        }
        (None, Some(path), None, None) => {
            let path = std::fs::canonicalize(path)
                .map_err(|err| format!("cannot resolve --wine {}: {err}", path.display()))?;
            let path = path
                .to_str()
                .ok_or_else(|| "--wine path is not valid UTF-8".to_string())?;
            Ok(TargetSpec::Wine {
                path: path.to_string(),
            })
        }
        (None, None, Some(name), None) => {
            let name = name.trim();
            if name.is_empty() {
                return Err("--process name must not be empty".to_string());
            }
            if name.contains('/') || name.contains('\\') {
                return Err(
                    "--process takes a process name, not a path; use --wine for a PE path"
                        .to_string(),
                );
            }
            Ok(TargetSpec::Name {
                name: name.to_string(),
            })
        }
        (None, None, None, Some(app_id)) => {
            if app_id == 0 {
                return Err("--steam app id must be greater than zero".to_string());
            }
            Ok(TargetSpec::Steam { app_id })
        }
        _ => Err("exactly one of --exe, --wine, --process, or --steam is required".to_string()),
    }
}

pub fn build_add(input: AddInput) -> Result<AddProfile, String> {
    validate_name(&input.name)?;
    let target = build_target(&input)?;
    let mode = validate_mode_links(
        ModeInput {
            filter: input.filter.as_deref(),
            route: input.route.as_deref(),
            allow_cidrs: &input.allow_cidrs,
            deny_cidrs: &input.deny_cidrs,
            except_cidrs: &input.except_cidrs,
            gateway: input.gateway.as_deref(),
            gateway6: input.gateway6.as_deref(),
            include_lan: input.include_lan,
            allow_ipv6: input.allow_ipv6,
            udp_only: input.udp_only,
            except_ports: &input.except_ports,
            except_sports: &input.except_sports,
        },
        &input.links,
    )?;
    Ok(AddProfile {
        name: input.name,
        target,
        mode,
        target_uid: input.target_uid,
    })
}

pub fn validate_mode(input: ModeInput<'_>) -> Result<ModeSpec, String> {
    validate_mode_links(input, &[])
}

pub fn validate_mode_links(input: ModeInput<'_>, links: &[String]) -> Result<ModeSpec, String> {
    if !links.is_empty() && (input.filter.is_some() || input.route.is_some()) {
        return Err("--link conflicts with --filter and --route".to_string());
    }
    if links.is_empty() {
        return validate_mode_classic(input);
    }
    if input.gateway.is_some() || input.gateway6.is_some() {
        return Err("--gateway and --gateway6 belong inside --link iface@gateway".to_string());
    }
    if !input.allow_cidrs.is_empty() || !input.deny_cidrs.is_empty() {
        return Err("--allow-cidr and --deny-cidr are only valid with --filter".to_string());
    }
    let parsed = parse_links(links, input.allow_ipv6)?;
    let primary = &parsed[0];
    let (except_ports, except_sports) =
        validate_route_ports(input.udp_only, input.except_ports, input.except_sports)?;
    validate_cidrs(input.except_cidrs)?;
    Ok(ModeSpec::Route {
        interface: primary.interface.clone(),
        gateway: primary.gateway.clone(),
        gateway6: primary.gateway6.clone(),
        links: parsed,
        include_lan: input.include_lan,
        allow_ipv6: input.allow_ipv6,
        udp_only: input.udp_only,
        except_ports,
        except_sports,
        except: input.except_cidrs.to_vec(),
    })
}

fn validate_mode_classic(input: ModeInput<'_>) -> Result<ModeSpec, String> {
    match (input.filter, input.route) {
        (Some(_), Some(_)) => Err("--filter and --route are mutually exclusive".to_string()),
        (None, None) => Err("exactly one of --filter, --route, or --link is required".to_string()),
        (Some(filter), None) => {
            if input.gateway.is_some()
                || input.gateway6.is_some()
                || input.include_lan
                || input.allow_ipv6
                || input.udp_only
                || !input.except_ports.is_empty()
                || !input.except_sports.is_empty()
            {
                return Err(
                    "--gateway, --gateway6, --include-lan, --allow-ipv6, --udp, and --except-port are only valid with --route"
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
            validate_cidrs(input.except_cidrs)?;
            let (except_ports, except_sports) =
                validate_route_ports(input.udp_only, input.except_ports, input.except_sports)?;
            let link = RouteLink {
                interface: interface.to_string(),
                gateway: input.gateway.map(str::to_string),
                gateway6: input.gateway6.map(str::to_string),
            };
            Ok(ModeSpec::Route {
                interface: link.interface.clone(),
                gateway: link.gateway.clone(),
                gateway6: link.gateway6.clone(),
                links: vec![link],
                include_lan: input.include_lan,
                allow_ipv6: input.allow_ipv6,
                udp_only: input.udp_only,
                except_ports,
                except_sports,
                except: input.except_cidrs.to_vec(),
            })
        }
    }
}

fn validate_route_ports(
    udp_only: bool,
    ports: &[u16],
    sports: &[u16],
) -> Result<(Vec<u16>, Vec<u16>), String> {
    if !udp_only && !ports.is_empty() {
        return Err("--except-port requires --udp".to_string());
    }
    if ports.len() > 32 {
        return Err("--except-port accepts at most 32 ports".to_string());
    }
    let mut except_ports = ports.to_vec();
    except_ports.sort_unstable();
    except_ports.dedup();
    if except_ports.contains(&0) {
        return Err("--except-port must be 1..=65535".to_string());
    }
    if !udp_only && !sports.is_empty() {
        return Err("--except-sport requires --udp".to_string());
    }
    if sports.len() > 64 {
        return Err("--except-sport accepts at most 64 ports".to_string());
    }
    let mut except_sports = sports.to_vec();
    except_sports.sort_unstable();
    except_sports.dedup();
    if except_sports.contains(&0) {
        return Err("--except-sport must be 1..=65535".to_string());
    }
    Ok((except_ports, except_sports))
}

/// Parse `iface`, `iface@ipv4`, `iface#ipv6`, or `iface@ipv4#ipv6`.
pub fn parse_link(text: &str) -> Result<RouteLink, String> {
    // The IPv6 half may stand alone (`iface#v6`), so split it before `@`.
    let (left, gateway6) = text
        .split_once('#')
        .map_or((text, None), |(left, gateway6)| (left, non_empty(gateway6)));
    let (interface, gateway) = left
        .split_once('@')
        .map_or((left, None), |(interface, gateway)| {
            (interface, non_empty(gateway))
        });
    if interface.is_empty()
        || interface.chars().any(|character| {
            character.is_whitespace() || character == '/' || character == '@' || character == '#'
        })
    {
        return Err(format!(
            "invalid --link '{text}': expected <iface>[@<ipv4>][#<ipv6>]"
        ));
    }
    if let Some(gateway) = &gateway {
        if !ipv4_valid(gateway) {
            return Err(format!("invalid IPv4 gateway '{gateway}' in --link {text}"));
        }
    }
    if let Some(gateway6) = &gateway6 {
        if !ipv6_valid(gateway6) {
            return Err(format!(
                "invalid IPv6 gateway '{gateway6}' in --link {text}"
            ));
        }
    }
    Ok(RouteLink {
        interface: interface.to_string(),
        gateway,
        gateway6,
    })
}

fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_string())
}

fn parse_links(links: &[String], allow_ipv6: bool) -> Result<Vec<RouteLink>, String> {
    if links.len() > 8 {
        return Err("--link accepts at most 8 interfaces".to_string());
    }
    let mut parsed: Vec<RouteLink> = Vec::with_capacity(links.len());
    for text in links {
        let link = parse_link(text)?;
        if parsed
            .iter()
            .any(|existing| existing.interface == link.interface)
        {
            return Err(format!("duplicate --link interface {}", link.interface));
        }
        if link.gateway6.is_some() && !allow_ipv6 {
            return Err("an IPv6 --link gateway requires --allow-ipv6".to_string());
        }
        parsed.push(link);
    }
    Ok(parsed)
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
                println!("existing sockets marked; restart is not required");
            }
            0
        }
        Err(err) => fail(err),
    }
}

pub fn open(socket: &Path, scope: OpenScope, policy: Option<ModeSpec>) -> i32 {
    let consumer = scope.consumer.clone();
    let handle = match client::send(socket, RequestOp::Open(scope)) {
        Ok(Some(data)) => match serde_json::from_value::<ScopeHandle>(data) {
            Ok(handle) => handle,
            Err(err) => {
                return fail(ClientError::Protocol(format!(
                    "invalid open response: {err}"
                )));
            }
        },
        Ok(None) => {
            return fail(ClientError::Protocol(
                "daemon returned no scope".to_string(),
            ))
        }
        Err(err) => return fail(err),
    };
    if let Some(policy) = policy {
        let result = client::send(
            socket,
            RequestOp::SetPolicy {
                profile: handle.profile.clone(),
                consumer: consumer.clone(),
                policy,
            },
        );
        let failure = match result {
            Ok(Some(data)) => match serde_json::from_value::<ProfileStatus>(data) {
                Ok(status) => {
                    print_profiles(std::slice::from_ref(&status));
                    None
                }
                Err(err) => Some(ClientError::Protocol(format!(
                    "invalid policy response: {err}"
                ))),
            },
            Ok(None) => Some(ClientError::Protocol(
                "daemon returned no policy".to_string(),
            )),
            Err(err) => Some(err),
        };
        if let Some(err) = failure {
            // The claim was created by this one-shot command; release it so a
            // failed policy does not leave an empty scope behind.
            let _ = client::send(
                socket,
                RequestOp::Close {
                    profile: handle.profile.clone(),
                    consumer,
                },
            );
            return fail(err);
        }
    }
    println!(
        "opened {} consumers={} state={} attached={} pids={}",
        handle.profile,
        handle.consumers.join(","),
        handle.state,
        handle.attached,
        handle
            .pids
            .iter()
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    0
}

pub fn set_policy(socket: &Path, profile: String, consumer: String, policy: ModeSpec) -> i32 {
    match client::send(
        socket,
        RequestOp::SetPolicy {
            profile,
            consumer,
            policy,
        },
    ) {
        Ok(Some(data)) => match serde_json::from_value::<ProfileStatus>(data) {
            Ok(status) => {
                print_profiles(std::slice::from_ref(&status));
                0
            }
            Err(err) => fail(ClientError::Protocol(format!(
                "invalid policy response: {err}"
            ))),
        },
        Ok(None) => fail(ClientError::Protocol(
            "daemon returned no policy".to_string(),
        )),
        Err(err) => fail(err),
    }
}

pub fn close(socket: &Path, profile: String, consumer: String) -> i32 {
    match client::send(socket, RequestOp::Close { profile, consumer }) {
        Ok(Some(data)) => match serde_json::from_value::<CloseResult>(data) {
            Ok(result) => {
                println!(
                    "closed {} consumer released={} scope_removed={} consumers={}",
                    result.profile,
                    result.released,
                    result.removed,
                    result.consumers.join(",")
                );
                0
            }
            Err(err) => fail(ClientError::Protocol(format!(
                "invalid close response: {err}"
            ))),
        },
        Ok(None) => fail(ClientError::Protocol(
            "daemon returned no close result".to_string(),
        )),
        Err(err) => fail(err),
    }
}

pub fn resolve(
    socket: &Path,
    profile: Option<String>,
    target: Option<TargetSpec>,
    uid: u32,
) -> i32 {
    match client::send(
        socket,
        RequestOp::Resolve {
            profile,
            target,
            target_uid: Some(uid),
        },
    ) {
        Ok(Some(data)) => match serde_json::from_value::<ProfileStatus>(data) {
            Ok(status) => {
                print_profiles(std::slice::from_ref(&status));
                0
            }
            Err(err) => fail(ClientError::Protocol(format!(
                "invalid resolve response: {err}"
            ))),
        },
        Ok(None) => fail(ClientError::Protocol(
            "daemon returned no profile".to_string(),
        )),
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
    let mut consumers_width = "CONSUMERS".len();
    let mut policies_width = "POLICIES".len();
    for profile in profiles {
        name_width = name_width.max(profile.id.len());
        mode_width = mode_width.max(profile.mode.len());
        target_width = target_width.max(profile.target.len());
        attached_width = attached_width.max(profile.attached.len());
        consumers_width = consumers_width.max(profile.consumers.join(",").len());
        policies_width = policies_width.max(profile.policies.join(",").len());
    }
    println!(
        "{:<name_width$}  {:<mode_width$}  {:<7}  {:<target_width$}  {:<attached_width$}  {:<consumers_width$}  {:<policies_width$}  PIDS",
        "NAME", "MODE", "ENABLED", "TARGET", "ATTACHED", "CONSUMERS", "POLICIES"
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
            "{:<name_width$}  {:<mode_width$}  {:<7}  {:<target_width$}  {:<attached_width$}  {:<consumers_width$}  {:<policies_width$}  {pids}",
            profile.id,
            profile.mode,
            enabled,
            profile.target,
            profile.attached,
            profile.consumers.join(","),
            profile.policies.join(",")
        );
        let interface_width = profile
            .links
            .iter()
            .map(|link| link.interface.len())
            .max()
            .unwrap_or(0);
        let gateway_width = profile
            .links
            .iter()
            .map(|link| {
                link.gateway
                    .as_deref()
                    .or(link.gateway6.as_deref())
                    .map_or(1, str::len)
            })
            .max()
            .unwrap_or(1);
        for link in &profile.links {
            let gateway = link
                .gateway
                .as_deref()
                .or(link.gateway6.as_deref())
                .unwrap_or("-");
            let rtt = link
                .rtt_ms
                .map_or_else(|| "-".to_string(), |rtt| format!("{rtt}ms"));
            println!(
                "  link {:<interface_width$}  {:<gateway_width$}  {:<4}  {:<5}  {}",
                link.interface,
                gateway,
                link.phase,
                rtt,
                if link.active { "active" } else { "-" }
            );
        }
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
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
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
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
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
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
        })
        .is_ok());
        assert!(mode(ModeInput {
            filter: Some("allow"),
            route: None,
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
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
            except_cidrs: &[],
            gateway: Some("192.0.2.1"),
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
        })
        .is_err());

        let error = mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: Some("192.0.2.1"),
            gateway6: Some("2001:db8::1"),
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
        })
        .expect_err("gateway6 without ipv6");
        assert!(error.contains("--allow-ipv6"));
    }

    #[test]
    fn udp_route_carries_its_source_port_pins() {
        let spec = mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: true,
            except_ports: &[],
            except_sports: &[52665, 49227, 52665],
        })
        .expect("valid udp route");
        match spec {
            ModeSpec::Route { except_sports, .. } => assert_eq!(except_sports, vec![49227, 52665]),
            _ => panic!("expected route"),
        }

        let error = mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[],
            except_sports: &[52665],
        })
        .expect_err("a source pin only means something on a UDP route");
        assert!(error.contains("--except-sport requires --udp"));
    }

    #[test]
    fn udp_route_carries_its_port_exceptions() {
        let spec = mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: true,
            except_ports: &[53, 53, 0],
            except_sports: &[],
        })
        .expect_err("port zero is invalid");
        assert!(spec.contains("1..=65535"));

        let spec = mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: true,
            except_ports: &[53, 1900, 53],
            except_sports: &[],
        })
        .expect("valid udp route");
        match spec {
            ModeSpec::Route {
                udp_only,
                except_ports,
                ..
            } => {
                assert!(udp_only);
                assert_eq!(except_ports, vec![53, 1900]);
            }
            _ => panic!("expected route"),
        }

        assert!(mode(ModeInput {
            filter: None,
            route: Some("tun0"),
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: false,
            except_ports: &[53],
            except_sports: &[],
        })
        .is_err());
    }

    #[test]
    fn wine_target_builds_from_flag() {
        let path = std::env::temp_dir().join(format!("netscope-wine-{}.exe", std::process::id()));
        std::fs::write(&path, b"MZ").expect("write fake PE");
        let profile = build_add(AddInput {
            name: "wine-app".to_string(),
            wine: Some(path.clone()),
            filter: Some("drop".to_string()),
            target_uid: 1000,
            ..AddInput::default()
        })
        .expect("wine target");
        let canonical = std::fs::canonicalize(&path).expect("canonical PE");
        assert_eq!(
            profile.target,
            TargetSpec::Wine {
                path: canonical.to_str().expect("utf8 path").to_string(),
            }
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn process_name_target_builds_from_flag() {
        let profile = build_add(AddInput {
            name: "running-game".to_string(),
            process: Some("Overwatch.exe".to_string()),
            filter: Some("drop".to_string()),
            target_uid: 1000,
            ..AddInput::default()
        })
        .expect("name target");
        assert_eq!(
            profile.target,
            TargetSpec::Name {
                name: "Overwatch.exe".to_string(),
            }
        );
    }

    #[test]
    fn process_name_rejects_paths() {
        let error = build_add(AddInput {
            name: "bad".to_string(),
            process: Some("/games/Overwatch.exe".to_string()),
            filter: Some("drop".to_string()),
            target_uid: 1000,
            ..AddInput::default()
        })
        .expect_err("path is not a process name");
        assert!(error.contains("not a path"));
    }

    #[test]
    fn exactly_one_target_flag_is_required() {
        let exe = PathBuf::from("/bin/true");
        let error = build_add(AddInput {
            name: "both".to_string(),
            exe: Some(exe.clone()),
            wine: Some(exe),
            filter: Some("drop".to_string()),
            target_uid: 1000,
            ..AddInput::default()
        })
        .expect_err("exe and wine conflict");
        assert!(error.contains("exactly one"));
    }

    #[test]
    fn names_match_the_shared_rule() {
        assert!(validate_name("game").is_ok());
        assert!(validate_name("game-1").is_ok());
        assert!(validate_name("Game").is_err());
        assert!(validate_name("-game").is_err());
        assert!(validate_name("").is_err());
    }

    fn link_mode(allow_ipv6: bool) -> ModeInput<'static> {
        ModeInput {
            filter: None,
            route: None,
            allow_cidrs: &[],
            deny_cidrs: &[],
            except_cidrs: &[],
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6,
            udp_only: false,
            except_ports: &[],
            except_sports: &[],
        }
    }

    #[test]
    fn link_grammar_accepts_the_documented_forms() {
        let bare = parse_link("enp7s0f4u1").expect("bare interface");
        assert_eq!(bare.interface, "enp7s0f4u1");
        assert_eq!(bare.gateway, None);
        assert_eq!(bare.gateway6, None);

        let v4 = parse_link("enp7s0f4u1@10.0.0.1").expect("ipv4 gateway");
        assert_eq!(v4.interface, "enp7s0f4u1");
        assert_eq!(v4.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(v4.gateway6, None);

        let dual = parse_link("enp7s0f4u1@10.0.0.1#2001:db8::1").expect("both gateways");
        assert_eq!(dual.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(dual.gateway6.as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn link_grammar_rejects_bad_forms() {
        for text in [
            "",
            "@10.0.0.1",
            "eth 0",
            "eth/0",
            "eth0@not-an-ip",
            "eth0@10.0.0.1#not-an-ip",
        ] {
            assert!(parse_link(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn link_list_rejects_duplicates_and_more_than_eight() {
        let duplicate = vec!["eth0".to_string(), "eth0@10.0.0.1".to_string()];
        let error = validate_mode_links(link_mode(false), &duplicate).expect_err("duplicate");
        assert!(error.contains("duplicate"), "{error}");

        let nine: Vec<String> = (0..9).map(|index| format!("eth{index}")).collect();
        let error = validate_mode_links(link_mode(false), &nine).expect_err("nine links");
        assert!(error.contains("at most 8"), "{error}");
    }

    #[test]
    fn ipv6_link_gateway_requires_allow_ipv6() {
        let links = vec!["eth0#2001:db8::1".to_string()];
        let error = validate_mode_links(link_mode(false), &links).expect_err("v6 without allow");
        assert!(error.contains("--allow-ipv6"), "{error}");
        assert!(validate_mode_links(link_mode(true), &links).is_ok());
    }

    #[test]
    fn link_conflicts_with_route_and_gateway() {
        let links = vec!["eth0".to_string()];
        let error = validate_mode_links(
            ModeInput {
                route: Some("tun0"),
                ..link_mode(false)
            },
            &links,
        )
        .expect_err("route and link conflict");
        assert!(error.contains("conflicts"), "{error}");

        let error = validate_mode_links(
            ModeInput {
                gateway: Some("10.0.0.1"),
                ..link_mode(false)
            },
            &links,
        )
        .expect_err("gateway outside link");
        assert!(error.contains("belong inside --link"), "{error}");
    }

    #[test]
    fn first_link_mirrors_into_the_primary_fields() {
        let links = vec!["eth0@10.0.0.1".to_string(), "eth1@10.0.1.1".to_string()];
        let spec = validate_mode_links(link_mode(false), &links).expect("two links");
        match spec {
            ModeSpec::Route {
                interface,
                gateway,
                links,
                ..
            } => {
                assert_eq!(interface, "eth0");
                assert_eq!(gateway.as_deref(), Some("10.0.0.1"));
                assert_eq!(links.len(), 2);
                assert_eq!(links[1].interface, "eth1");
            }
            other => panic!("expected route, got {other:?}"),
        }
    }
}
