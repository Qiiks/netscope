# Security

netscope is alpha software and has not received an independent security audit. Treat it as a convenience tool for scoping one application's traffic, not as a hardened security boundary against a hostile local user or a compromised kernel.

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/Qiiks/netscope/security/advisories/new). Do not open a public issue for a vulnerability.

Include the netscope version, distribution, kernel, steps to reproduce, and whether the daemon runs under systemd or manually. A reviewed support bundle helps; see [Support bundle](support-bundle.md). We aim to acknowledge a report within seven days and to allow a fix and release before public disclosure.

## Trust boundary

`netscoped` runs as root. It must, because it creates cgroups, opens a fanotify permission group, and invokes `nft` and `ip`. The privileged surface is deliberately small:

| Component | Privilege | Exposure |
|---|---|---|
| `netscoped` | root | Unix socket, fanotify, child `nft`/`ip` processes |
| `netscope` CLI | user | Unix socket |
| Kernel | — | cgroup v2, fanotify, nftables, policy routing |

The daemon opens **one** Unix socket at `/run/netscope/control.sock`. It does not open a TCP or UDP listener, does not serve HTTP, and has no remote UI, telemetry, or analytics.

The socket is owned by `root:netscope` with mode `0660`. Only root and members of the `netscope` group can connect. Joining that group is equivalent to trusting the user to manage profiles for their own UID; do not add untrusted accounts.

## Authentication and authorization

There are no passwords or tokens. The daemon uses the peer credentials of the Unix socket connection:

- A member of the `netscope` group can add and manage profiles owned by their own UID.
- Root can manage any profile and can pass `--uid` to create one for another user. `--uid` is refused for non-root callers.
- A profile records its owner UID. A non-root user cannot remove, enable, or disable another user's profile.
- The CLI does not send a claimed UID that the daemon blindly trusts; ownership comes from the socket peer, except for the root-only `--uid` path.

## Input validation

All requests are JSON lines with a 64 KiB request limit and a 64 KiB response limit. The daemon rejects malformed JSON, oversized requests, unknown operations, and an API version it does not support. The protocol version is `1`.

Before any host change, the daemon validates:

- **Profile IDs:** 1–32 characters, `[a-z0-9][a-z0-9-]*`. The ID is used in cgroup and nftables table names, and `-` is mapped to `_` for nftables.
- **Executable paths:** canonicalized. The daemon records the device and inode and matches on that identity, re-resolving it when the file at the recorded path changes.
- **Windows PE paths:** `--wine` takes an absolute path. The daemon canonicalizes it, requires a regular file, and requires the first two bytes to be `MZ` before recording its device and inode. No ELF check is applied.
- **Process names:** `--process` takes a name, not a path; it is rejected if empty, longer than 64 printable characters, or contains a path separator. The daemon refuses `netscope`, `netscoped`, and the shared `wineserver` as name targets.
- **Steam app IDs:** numeric, within the profile target type.
- **CIDRs:** parsed as IPv4 or IPv6 networks. Invalid input is rejected, not passed through.
- **Interfaces and gateways:** passed as separate arguments to `ip`; no shell is involved.
- **Numeric values:** profile count is bounded at 32, and index, mark, table, and priority allocation is bounded.

The daemon never invokes a shell, never evaluates a profile-controlled string as shell code, and never writes attacker-controlled text into an nftables rule without parsing or a fixed grammar.

## Root daemon risks

A root daemon is a real risk if it has a bug. Reduce exposure:

- Keep the `netscope` group small. Membership is a privilege.
- Keep `/etc/netscope/config.toml` and `/var/lib/netscope/state.json` root-owned and not writable by group members.
- Do not expose `/run/netscope/control.sock` through a bind mount, a container, or a network filesystem.
- Run the shipped systemd unit, which supervises and restarts the daemon. It sets `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `RestrictNamespaces=yes`, and a bound set of system calls. `ProtectControlGroups=no` and `ProtectKernelModules=no` are deliberate: the daemon must write the cgroup hierarchy, and `nft_socket` may autoload on the first cgroup rule.
- Review the unit's sandboxing before changing it. It grants `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, and `CAP_SYS_PTRACE`; removing one breaks attachment or rule installation.
- Treat a kernel or nftables vulnerability as outside netscope's boundary; netscope is a consumer of those interfaces.

## What netscope does not protect

netscope scopes traffic from processes it successfully attaches to a profile cgroup. It does **not** protect:

- **Sockets opened before attachment.** An existing TCP connection keeps its original cgroup and is not matched. Restart the app. For a Wine target this includes sockets the loader opened before it opened the PE. A `--process` target is always attached late, so this applies to every name target.
- **Name collisions.** A `--process` target matches every process with that `comm` or argv basename, including another user's process if it runs under the same UID. Both are attached. Use `--exe` or `--wine` when the identity must be exact.
- **Non-Wine processes that open a selected PE.** A `--wine` profile marks the file, so the daemon sees every open of it, but it attaches only a Wine process whose command line names the selected PE. Any other process that opens the same file — a file manager, an indexer, a scanner — is allowed and left unscoped. `wineserver` is never attached; it may open the PE for a loader, but it is shared across Wine applications. Children the attached process starts stay in the same cgroup.
- **Processes that escape attachment.** A process that was never matched by the exec hook or the poller is unscoped. Privileged processes can move themselves out of the cgroup; netscope does not fight that.
- **Kernel-generated traffic with no local socket.** Forwarded packets, some ICMP errors, and other locally generated traffic that is not attributed to a socket in the cgroup are not matched.
- **Traffic forwarded for another host.** A router or NAT workload forwarding packets on behalf of another machine is out of scope.
- **DNS decisions.** netscope matches destinations, not names. A name that resolves to an unexpected address is filtered or routed by address.
- **The tunnel itself.** Route mode does not create, authenticate, or encrypt a tunnel. It sends marked traffic to an interface you configured.
- **A determined local attacker with root.** Root can change cgroups, nftables, and routes. netscope is not a defense against root.

## Fail-open behavior

Route mode fails closed only while its rules are installed and the tunnel is down. Removing the profile, a clean daemon stop, a reboot, or manual removal of the table is fail-open: marked traffic falls through to the main routing table. See [Route mode](modes/route.md).

Filter mode is fail-open in the same operational sense: if the profile or daemon is removed, packets are no longer dropped.

## Supply chain and build

- The workspace is dual-licensed MIT OR Apache-2.0.
- No dependencies are vendored; builds use crates.io through Cargo.
- Release tarballs should ship with a SHA-256 file; verify it before installing.
- CI runs formatting, Clippy with warnings denied, tests, a release build, and an mdBook build.
- No external assets, fonts, analytics, or tracking scripts are loaded by these docs or the binaries.
