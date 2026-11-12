# netscope-client

[![Crates.io](https://img.shields.io/crates/v/netscope-client.svg)](https://crates.io/crates/netscope-client)
[![Documentation](https://docs.rs/netscope-client/badge.svg)](https://docs.rs/netscope-client)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Qiiks/netscope)

Typed Rust client SDK for the [netscope](https://github.com/Qiiks/netscope) daemon over its Unix domain control socket (`/run/netscope/control.sock`).

Netscope provides per-process network scoping on Linux using cgroup v2, nftables, and policy routing without requiring game launch wrappers.

## Features

- **Direct Unix Socket IPC:** Speaks newline-delimited JSON (NDJSON) directly to `netscoped`.
- **Peer-Held Scopes (`Hold::Peer`):** Ties the scope lifecycle to the client's socket connection. If the client exits or crashes, the kernel drops the socket and Netscope automatically tears down the policy rules and cleans up the cgroup.
- **Shared Scopes:** Multiple consumers (e.g. ExitLink for UDP routing and Dropship for server firewall filtering) can attach to the same process simultaneously.
- **Zero-Wrapper Attach:** Scopes attach running processes by name (`Overwatch.exe`) or PE path at `execve` via fanotify.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
netscope-client = "0.3.0"
```

```rust
use netscope_client::{Client, FilterDefault, Hold, PolicySpec, TargetSpec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Connect to the local netscope daemon
    let mut client = Client::connect()?;

    // 2. Open a shared scope for Overwatch
    let handle = client.open_scope(netscope_client::OpenScope {
        consumer: "my-tool".into(),
        name: Some("my-tool-scope".into()),
        target: TargetSpec::Name { name: "Overwatch.exe".into() },
        target_uid: unsafe { libc::getuid() },
        hold: Hold::Peer,
    })?;

    println!("Scope opened: profile={}", handle.profile);

    // 3. Apply a firewall filter policy (block specific server subnets)
    client.set_policy(
        &handle.profile,
        "my-tool",
        PolicySpec::Filter {
            default: FilterDefault::Allow,
            allow_cidrs: vec![],
            deny_cidrs: vec!["34.142.0.0/16".into()],
        },
    )?;

    // Scope stays active as long as `client` socket is open.
    // Or call client.close_scope(&handle.profile, "my-tool") explicitly.
    Ok(())
}
```

## Documentation

Full protocol specifications and multi-language client examples (Go, Python, C, Shell) are available in the [Netscope Protocol Guide](https://qiiks.github.io/netscope/protocol.html).
