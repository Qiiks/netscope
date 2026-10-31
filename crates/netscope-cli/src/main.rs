mod cleanup;
mod client;
mod commands;
mod diagnostics;

use std::path::{Path, PathBuf};

use clap::{ArgGroup, Args, Parser, Subcommand};
use netscope_linux::types::{BundleArgs, DoctorArgs};

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
    /// Scope a native executable, Wine/Proton PE, or Steam app
    Add(AddArgs),
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
        .args(["exe", "wine", "steam"]),
))]
struct AddArgs {
    name: String,
    #[arg(long, value_name = "PATH")]
    exe: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    wine: Option<PathBuf>,
    #[arg(long, value_name = "APPID")]
    steam: Option<u32>,
    #[arg(
        long,
        value_name = "DEFAULT",
        value_parser = ["drop", "allow"],
        conflicts_with = "route",
        required_unless_present = "route"
    )]
    filter: Option<String>,
    #[arg(
        long,
        value_name = "IFACE",
        conflicts_with = "filter",
        required_unless_present = "filter"
    )]
    route: Option<String>,
    #[arg(long = "allow-cidr", value_name = "CIDR")]
    allow_cidr: Vec<String>,
    #[arg(long = "deny-cidr", value_name = "CIDR")]
    deny_cidr: Vec<String>,
    #[arg(long, value_name = "IPV4", requires = "route")]
    gateway: Option<String>,
    #[arg(long, value_name = "IPV6", requires = "allow_ipv6")]
    gateway6: Option<String>,
    #[arg(long, requires = "route")]
    include_lan: bool,
    #[arg(long, requires = "route")]
    allow_ipv6: bool,
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
        steam: args.steam,
        filter: args.filter,
        route: args.route,
        allow_cidrs: args.allow_cidr,
        deny_cidrs: args.deny_cidr,
        gateway: args.gateway,
        gateway6: args.gateway6,
        include_lan: args.include_lan,
        allow_ipv6: args.allow_ipv6,
        target_uid,
    };
    match commands::build_add(input) {
        Ok(profile) => commands::add(socket, profile),
        Err(message) => usage(&message),
    }
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
