mod cleanup;
mod client;
mod commands;
mod diagnostics;

use std::path::{Path, PathBuf};

use clap::{ArgGroup, Args, Parser, Subcommand};
use netscope_linux::protocol::OpenScope;
use netscope_linux::types::{BundleArgs, DoctorArgs, Hold};

// diagnostics keeps `support_bundle` for default-options callers; main always
// passes explicit options through `support_bundle_with`.
const _: fn(&BundleArgs) -> anyhow::Result<PathBuf> = diagnostics::support_bundle;

#[derive(Parser)]
#[command(
    name = "netscope",
    version,
    about = "Per-application network scoping for Linux"
)]
struct Cli {
    #[arg(long, global = true, hide = true, value_name = "PATH")]
    socket: Option<PathBuf>,
    #[arg(long, global = true, hide = true, value_name = "UID")]
    uid: Option<u32>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
// Parsed once at startup; boxing arguments would only add indirection.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Show the daemon and its profiles
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List every profile, enabled or disabled
    List {
        #[arg(long)]
        json: bool,
    },
    /// Scope a native executable, process name, Wine/Proton PE, or Steam app
    Add(AddArgs),
    /// Open a shared scope for one consumer and optionally set its policy
    Open(OpenArgs),
    /// Replace one consumer's policy on a shared scope
    Policy(PolicyArgs),
    /// Release one consumer's claim on a shared scope
    Close {
        profile: String,
        #[arg(long)]
        consumer: String,
    },
    /// Find a shared scope by id or target
    Resolve {
        #[arg(long)]
        profile: Option<String>,
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Remove a profile and its rules
    Remove { name: String },
    /// Enable a disabled profile
    Enable { name: String },
    /// Disable a profile without removing it
    Disable { name: String },
    /// Re-stat targets and attach already-running apps
    Refresh,
    /// Run diagnostic checks
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Collect a redacted troubleshooting archive
    SupportBundle {
        #[arg(long, value_name = "PATH", help = "Write the archive to PATH")]
        output: Option<PathBuf>,
        #[arg(long, help = "Include the daemon journal (logs.txt)")]
        include_logs: bool,
        #[arg(long, help = "Include config.toml")]
        include_config: bool,
        #[arg(long, help = "Disable redaction; requires --acknowledge")]
        no_redact: bool,
        #[arg(long, help = "Confirm writing an unredacted bundle")]
        acknowledge: bool,
    },
    /// Show the daemon journal
    Logs {
        #[arg(
            short = 'n',
            long = "lines",
            value_name = "LINES",
            default_value_t = 50
        )]
        lines: usize,
    },
    /// Remove runtime rules and cgroups while the daemon is stopped
    Cleanup {
        #[arg(long, required = true)]
        all: bool,
        #[arg(long)]
        purge: bool,
    },
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["exe", "wine", "process", "steam"]),
))]
#[command(group(
    ArgGroup::new("route_mode")
        .multiple(false)
        .args(["route", "link"]),
))]
struct AddArgs {
    name: String,
    #[arg(long, value_name = "PATH")]
    exe: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    wine: Option<PathBuf>,
    #[arg(long, value_name = "NAME")]
    process: Option<String>,
    #[arg(long, value_name = "APPID")]
    steam: Option<u32>,
    #[arg(
        long,
        value_name = "DEFAULT",
        value_parser = ["drop", "allow"],
        conflicts_with_all = ["route", "link"],
        required_unless_present_any = ["route", "link"]
    )]
    filter: Option<String>,
    #[arg(
        long,
        value_name = "IFACE",
        conflicts_with_all = ["filter", "link"],
        required_unless_present_any = ["filter", "link"]
    )]
    route: Option<String>,
    /// Ordered route link: <iface>[@<ipv4>][#<ipv6>] (repeatable, max 8)
    #[arg(long = "link", value_name = "LINK", conflicts_with_all = ["filter", "route"])]
    link: Vec<String>,
    #[arg(long = "allow-cidr", value_name = "CIDR")]
    allow_cidr: Vec<String>,
    #[arg(long = "deny-cidr", value_name = "CIDR")]
    deny_cidr: Vec<String>,
    #[arg(long = "except", value_name = "CIDR", requires = "route_mode")]
    except_cidr: Vec<String>,
    #[arg(long, value_name = "IPV4", requires = "route")]
    gateway: Option<String>,
    #[arg(long, value_name = "IPV6", requires = "allow_ipv6")]
    gateway6: Option<String>,
    #[arg(long, requires = "route_mode")]
    include_lan: bool,
    #[arg(long, requires = "route_mode")]
    allow_ipv6: bool,
    /// Mark only IPv4 UDP; TCP keeps its normal route
    #[arg(long, requires = "route_mode")]
    udp: bool,
    /// UDP destination port that stays direct (repeatable)
    #[arg(long = "except-port", value_name = "PORT", requires = "route_mode")]
    except_port: Vec<u16>,
    /// UDP source port that already had a flow when the route opened and must
    /// stay direct (repeatable)
    #[arg(long = "except-sport", value_name = "PORT", requires = "route_mode")]
    except_sport: Vec<u16>,
}

#[derive(Args)]
struct TargetArgs {
    #[arg(long, value_name = "PATH")]
    exe: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    wine: Option<PathBuf>,
    #[arg(long, value_name = "NAME")]
    process: Option<String>,
    #[arg(long, value_name = "APPID")]
    steam: Option<u32>,
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["exe", "wine", "process", "steam"]),
))]
#[command(group(
    ArgGroup::new("route_mode")
        .multiple(false)
        .args(["route", "link"]),
))]
struct OpenArgs {
    #[arg(long)]
    consumer: String,
    #[arg(long)]
    name: Option<String>,
    #[command(flatten)]
    target: TargetArgs,
    #[arg(
        long,
        value_name = "DEFAULT",
        value_parser = ["drop", "allow"],
        conflicts_with_all = ["route", "link"]
    )]
    filter: Option<String>,
    #[arg(
        long,
        value_name = "IFACE",
        conflicts_with_all = ["filter", "link"]
    )]
    route: Option<String>,
    /// Ordered route link: <iface>[@<ipv4>][#<ipv6>] (repeatable, max 8)
    #[arg(long = "link", value_name = "LINK", conflicts_with_all = ["filter", "route"])]
    link: Vec<String>,
    #[arg(long = "allow-cidr", value_name = "CIDR")]
    allow_cidr: Vec<String>,
    #[arg(long = "deny-cidr", value_name = "CIDR")]
    deny_cidr: Vec<String>,
    #[arg(long = "except", value_name = "CIDR", requires = "route_mode")]
    except_cidr: Vec<String>,
    #[arg(long, value_name = "IPV4", requires = "route")]
    gateway: Option<String>,
    #[arg(long, value_name = "IPV6", requires = "allow_ipv6")]
    gateway6: Option<String>,
    #[arg(long, requires = "route_mode")]
    include_lan: bool,
    #[arg(long, requires = "route_mode")]
    allow_ipv6: bool,
    /// Mark only IPv4 UDP; TCP keeps its normal route
    #[arg(long, requires = "route_mode")]
    udp: bool,
    /// UDP destination port that stays direct (repeatable)
    #[arg(long = "except-port", value_name = "PORT", requires = "route_mode")]
    except_port: Vec<u16>,
    /// UDP source port that already had a flow when the route opened and must
    /// stay direct (repeatable)
    #[arg(long = "except-sport", value_name = "PORT", requires = "route_mode")]
    except_sport: Vec<u16>,
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("route_mode")
        .multiple(false)
        .args(["route", "link"]),
))]
struct PolicyArgs {
    profile: String,
    #[arg(long)]
    consumer: String,
    #[arg(
        long,
        value_name = "DEFAULT",
        value_parser = ["drop", "allow"],
        conflicts_with_all = ["route", "link"],
        required_unless_present_any = ["route", "link"]
    )]
    filter: Option<String>,
    #[arg(
        long,
        value_name = "IFACE",
        conflicts_with_all = ["filter", "link"],
        required_unless_present_any = ["filter", "link"]
    )]
    route: Option<String>,
    /// Ordered route link: <iface>[@<ipv4>][#<ipv6>] (repeatable, max 8)
    #[arg(long = "link", value_name = "LINK", conflicts_with_all = ["filter", "route"])]
    link: Vec<String>,
    #[arg(long = "allow-cidr", value_name = "CIDR")]
    allow_cidr: Vec<String>,
    #[arg(long = "deny-cidr", value_name = "CIDR")]
    deny_cidr: Vec<String>,
    #[arg(long = "except", value_name = "CIDR", requires = "route_mode")]
    except_cidr: Vec<String>,
    #[arg(long, value_name = "IPV4", requires = "route")]
    gateway: Option<String>,
    #[arg(long, value_name = "IPV6", requires = "allow_ipv6")]
    gateway6: Option<String>,
    #[arg(long, requires = "route_mode")]
    include_lan: bool,
    #[arg(long, requires = "route_mode")]
    allow_ipv6: bool,
    /// Mark only IPv4 UDP; TCP keeps its normal route
    #[arg(long, requires = "route_mode")]
    udp: bool,
    /// UDP destination port that stays direct (repeatable)
    #[arg(long = "except-port", value_name = "PORT", requires = "route_mode")]
    except_port: Vec<u16>,
    /// UDP source port that already had a flow when the route opened and must
    /// stay direct (repeatable)
    #[arg(long = "except-sport", value_name = "PORT", requires = "route_mode")]
    except_sport: Vec<u16>,
}

fn main() {
    let cli = Cli::parse();
    if unsafe { libc::geteuid() } != 0 && cli.uid.is_some() {
        std::process::exit(usage("--uid is only accepted from root"));
    }
    let socket = client::socket_path(cli.socket.as_deref());
    let code = match cli.command {
        Cmd::Status { json } => commands::status(&socket, json),
        Cmd::List { json } => commands::list(&socket, json),
        Cmd::Add(args) => add(args, cli.uid, &socket),
        Cmd::Open(args) => open(args, cli.uid, &socket),
        Cmd::Policy(args) => policy(args, &socket),
        Cmd::Close { profile, consumer } => commands::close(&socket, profile, consumer),
        Cmd::Resolve { profile, target } => resolve(profile, target, cli.uid, &socket),
        Cmd::Remove { name } => with_valid_name(name, &socket, commands::remove),
        Cmd::Enable { name } => with_valid_name(name, &socket, commands::enable),
        Cmd::Disable { name } => with_valid_name(name, &socket, commands::disable),
        Cmd::Refresh => commands::refresh(&socket),
        Cmd::Doctor { json } => diagnostics::doctor(&DoctorArgs {
            socket: cli.socket,
            json,
        }),
        Cmd::SupportBundle {
            output,
            include_logs,
            include_config,
            no_redact,
            acknowledge,
        } => {
            if no_redact && !acknowledge {
                usage("refusing to write an unredacted bundle; add --acknowledge to confirm")
            } else if unsafe { libc::geteuid() } != 0 {
                eprintln!("netscope: support-bundle requires root: sudo netscope support-bundle");
                4
            } else {
                let args = BundleArgs {
                    socket: cli.socket,
                    output,
                };
                let options = diagnostics::BundleOptions {
                    include_logs,
                    include_config,
                    redact: !no_redact,
                    acknowledge,
                };
                match diagnostics::support_bundle_with(&args, &options) {
                    Ok(path) => {
                        println!("support bundle: {}", path.display());
                        println!("review before uploading");
                        0
                    }
                    Err(err) => {
                        eprintln!("netscope: {err:#}");
                        1
                    }
                }
            }
        }
        Cmd::Logs { lines } => commands::logs(lines),
        Cmd::Cleanup { all, purge } => cleanup::run(cli.socket.as_deref(), all, purge),
    };
    std::process::exit(code);
}

fn add(args: AddArgs, uid: Option<u32>, socket: &Path) -> i32 {
    let target_uid = match resolve_target_uid(uid) {
        Ok(uid) => uid,
        Err(message) => return usage(&message),
    };
    let input = commands::AddInput {
        name: args.name,
        exe: args.exe,
        wine: args.wine,
        process: args.process,
        steam: args.steam,
        filter: args.filter,
        route: args.route,
        links: args.link,
        allow_cidrs: args.allow_cidr,
        deny_cidrs: args.deny_cidr,
        except_cidrs: args.except_cidr,
        gateway: args.gateway,
        gateway6: args.gateway6,
        include_lan: args.include_lan,
        allow_ipv6: args.allow_ipv6,
        udp_only: args.udp,
        except_ports: args.except_port,
        except_sports: args.except_sport,
        target_uid,
    };
    match commands::build_add(input) {
        Ok(profile) => commands::add(socket, profile),
        Err(message) => usage(&message),
    }
}

fn open(args: OpenArgs, uid: Option<u32>, socket: &Path) -> i32 {
    if args.filter.is_none()
        && args.route.is_none()
        && args.link.is_empty()
        && (!args.allow_cidr.is_empty() || !args.deny_cidr.is_empty())
    {
        return usage("--allow-cidr and --deny-cidr need --filter, --route, or --link");
    }
    let target_uid = match resolve_target_uid(uid) {
        Ok(uid) => uid,
        Err(message) => return usage(&message),
    };
    let input = commands::AddInput {
        name: args.name.clone().unwrap_or_default(),
        exe: args.target.exe,
        wine: args.target.wine,
        process: args.target.process,
        steam: args.target.steam,
        filter: args.filter.clone(),
        route: args.route.clone(),
        links: args.link.clone(),
        allow_cidrs: args.allow_cidr.clone(),
        deny_cidrs: args.deny_cidr.clone(),
        except_cidrs: args.except_cidr.clone(),
        gateway: args.gateway.clone(),
        gateway6: args.gateway6.clone(),
        include_lan: args.include_lan,
        allow_ipv6: args.allow_ipv6,
        udp_only: args.udp,
        except_ports: args.except_port.clone(),
        except_sports: args.except_sport.clone(),
        target_uid,
    };
    let target = match commands::build_target(&input) {
        Ok(target) => target,
        Err(message) => return usage(&message),
    };
    let policy = if args.filter.is_some() || args.route.is_some() || !args.link.is_empty() {
        match commands::validate_mode_links(
            commands::ModeInput {
                filter: args.filter.as_deref(),
                route: args.route.as_deref(),
                allow_cidrs: &args.allow_cidr,
                deny_cidrs: &args.deny_cidr,
                except_cidrs: &args.except_cidr,
                gateway: args.gateway.as_deref(),
                gateway6: args.gateway6.as_deref(),
                include_lan: args.include_lan,
                allow_ipv6: args.allow_ipv6,
                udp_only: args.udp,
                except_ports: &args.except_port,
                except_sports: &args.except_sport,
            },
            &args.link,
        ) {
            Ok(policy) => Some(policy),
            Err(message) => return usage(&message),
        }
    } else {
        None
    };
    commands::open(
        socket,
        OpenScope {
            consumer: args.consumer,
            target,
            target_uid,
            name: args.name,
            hold: Hold::Persistent,
        },
        policy,
    )
}

fn policy(args: PolicyArgs, socket: &Path) -> i32 {
    let policy = match commands::validate_mode_links(
        commands::ModeInput {
            filter: args.filter.as_deref(),
            route: args.route.as_deref(),
            allow_cidrs: &args.allow_cidr,
            deny_cidrs: &args.deny_cidr,
            except_cidrs: &args.except_cidr,
            gateway: args.gateway.as_deref(),
            gateway6: args.gateway6.as_deref(),
            include_lan: args.include_lan,
            allow_ipv6: args.allow_ipv6,
            udp_only: args.udp,
            except_ports: &args.except_port,
            except_sports: &args.except_sport,
        },
        &args.link,
    ) {
        Ok(policy) => policy,
        Err(message) => return usage(&message),
    };
    commands::set_policy(socket, args.profile, args.consumer, policy)
}

fn resolve(profile: Option<String>, target: TargetArgs, uid: Option<u32>, socket: &Path) -> i32 {
    if profile.is_none()
        && target.exe.is_none()
        && target.wine.is_none()
        && target.process.is_none()
        && target.steam.is_none()
    {
        return usage("resolve needs --profile or a target");
    }
    let target_uid = match resolve_target_uid(uid) {
        Ok(uid) => uid,
        Err(message) => return usage(&message),
    };
    let target = if profile.is_some() {
        None
    } else {
        let input = commands::AddInput {
            exe: target.exe,
            wine: target.wine,
            process: target.process,
            steam: target.steam,
            ..Default::default()
        };
        match commands::build_target(&input) {
            Ok(target) => Some(target),
            Err(message) => return usage(&message),
        }
    };
    commands::resolve(socket, profile, target, target_uid)
}

fn with_valid_name(name: String, socket: &Path, action: fn(&Path, String) -> i32) -> i32 {
    match commands::validate_name(&name) {
        Ok(()) => action(socket, name),
        Err(message) => usage(&message),
    }
}

fn resolve_target_uid(uid: Option<u32>) -> Result<u32, String> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(euid);
    }
    if let Some(uid) = uid {
        return Ok(uid);
    }
    if let Some(uid) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        return Ok(uid);
    }
    Err("run as the target user or pass --uid <n>".to_string())
}

fn usage(message: &str) -> i32 {
    eprintln!("netscope: {message}");
    2
}
