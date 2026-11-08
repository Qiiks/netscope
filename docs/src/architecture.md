# Architecture & Decisions

Netscope provides per-process network filtering and routing on Linux without requiring application wrappers (`LD_PRELOAD`, network namespaces, or launch prefixes). This document records the core architectural decisions, the alternatives considered, and the engineering rationale behind them.

---

## 1. Architectural Decisions and Rationale

| Area | Decision | Considered & Rejected | Engineering Rationale |
|---|---|---|---|
| **Kernel Primitive** | Standard upstream primitives: `cgroup v2` + `nftables` + `fanotify`. | Custom Linux kernel module (DKMS / eBPF LSM / out-of-tree driver). | While Windows requires a WFP callout kernel driver, building a Linux kernel module creates massive maintenance friction, breaks across kernel upgrades, and requires Secure Boot MOK signing. Combining fanotify (`FAN_OPEN_EXEC_PERM`) for pre-socket interception, cgroup v2 for hierarchy inheritance, and nftables `socket cgroupv2` matches provides full WFP-parity using standard kernel features (kernel >= 5.13). |
| **Shared Scopes** | Unified shared cgroups with multi-consumer policy chains (`<consumer>:filter`, `<consumer>:route`). | Isolated per-tool cgroups (e.g. `dropship-game` vs `exitlink-790`). | In Linux cgroup v2, a process can belong to only **one** leaf cgroup. If tool A and tool B each create their own cgroup, attaching a process to tool B silently pulls it out of tool A's cgroup, causing tool A's nftables selectors to match zero packets. Netscope creates one authoritative cgroup per process and evaluates multiple consumers' policies on independent chains. |
| **IPC & Lifecycle** | Unix domain control socket (`/run/netscope/control.sock`) speaking newline-delimited JSON with `Hold::Peer`. | CLI-only execution with persistent marker files. | CLI commands create persistent state. If a client app (like a game launcher, proxy, or firewall UI) crashes, persistent claims remain orphaned. Using a stream socket with `Hold::Peer` ties the scope and rules to the client's socket file descriptor: when the client process exits or crashes, the kernel closes the socket, and `netscoped` automatically cleans up the policy and cgroup. |
| **Late Socket Attach** | Process socket duplication via `pidfd_getfd` and direct `SO_MARK`. | Requiring application restarts, or relying purely on `socket cgroupv2`. | In Linux, sockets created before a process is moved into a cgroup retain their pre-existing socket attributes. To scope already-running applications without requiring a restart, the daemon iterates `/proc/<pid>/fd`, calls `pidfd_getfd` to duplicate datagram/stream sockets, and applies `SO_MARK`. A dedicated `socket mark` rule matches these existing sockets. |
| **Protocol Scoping** | Protocol-scoped marking (`udp_only: bool`) and source-port pins (`--except-sport`). | Uniform socket-marking across all protocols. | Marking all sockets in a cgroup inadvertently pulls TCP authentication/login sockets into UDP-only tunnels (like gaming VPNs), causing game auth disconnections. Protocol scoping restricts marking to `SOCK_DGRAM` on UDP-only routes, while `--except-sport` pins active match ports so existing established flows are not disrupted mid-game. |
| **Client SDK** | Zero-privilege `netscope-client` published to crates.io. | Bundling root code into application binaries, or requiring raw subprocess execs. | GUI applications (GPUI, egui, Electron) should never run with root privileges or `CAP_NET_ADMIN`. `netscope-client` is a safe, lightweight IPC crate with zero system dependencies that communicates with `netscoped` over the control socket. |

---

## 2. Subsystem Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                              Applications                              │
 │   Dropship (Filter Consumer)                 ExitLink (Route Consumer) │
 └───────────────────┬───────────────────────────────────┬────────────────┘
                     │                                   │
                     │  Unix Domain Socket (NDJSON)      │
                     ▼                                   ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     netscoped (System Daemon, Root)                    │
 │                                                                        │
 │  ┌─────────────────────┐   ┌─────────────────┐   ┌──────────────────┐  │
 │  │  Process Watcher    │   │  Scope Manager  │   │  nftables Engine │  │
 │  │  · fanotify hold    │   │  · cgroup v2    │   │  · inet tables   │  │
 │  │  · Wine PE loader   │   │  · multi-holds  │   │  · policy chains │  │
 │  │  · pidfd_getfd mark │   │  · generations  │   │  · priority sort │  │
 │  └─────────────────────┘   └─────────────────┘   └──────────────────┘  │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ Kernel Configuration
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                              Linux Kernel                              │
 │                                                                        │
 │   /sys/fs/cgroup/netscope/<profile>   (Single unified game cgroup)     │
 │                    │                                                   │
 │                    ▼                                                   │
 │   nftables table inet netscope_<profile>                               │
 │     ├── chain filter_dropship: ip daddr <blocked> drop                 │
 │     └── chain route_exitlink:  udp dport { ... } meta mark set 0x4e53  │
 │                    │                                                   │
 │                    ▼                                                   │
 │   ip rule pref 1000 fwmark 0x4e53 lookup 20000 (Policy Routing)        │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Attachment Strategies & Timing

Netscope provides three distinct attachment strategies depending on the application lifecycle:

### 1. Pre-Exec Attachment (Native ELF)
- **Mechanism:** `fanotify` marks the executable inode with `FAN_OPEN_EXEC_PERM`.
- **Timing:** Kernel holds the `execve` syscall before the binary entry point runs.
- **Guarantee:** The process is moved into `/sys/fs/cgroup/netscope/<profile>` before its very first instruction or socket is created.

### 2. Pre-Open Attachment (Wine / Proton PEs)
- **Mechanism:** `fanotify` marks the `.exe` Windows PE inode with `FAN_OPEN_PERM`.
- **Timing:** Kernel holds the Wine loader's open of the PE file. The daemon inspects `/proc` to find the Wine process loading the binary.
- **Guarantee:** The Wine process is attached before Windows game code initializes, ensuring 100% of game sockets are created inside the cgroup.

### 3. Late Attachment (Already-Running Processes)
- **Mechanism:** Polling scanner matches process `comm` or argv basename.
- **Timing:** Attached post-launch.
- **Guarantee:** Process is moved into the cgroup for future sockets, and existing open sockets are duplicated via `pidfd_getfd` and marked with `SO_MARK`, routing active flows without restarting the app.

---

## 4. Security & Privilege Boundaries

1. **Daemon Boundary:** `netscoped` requires `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` to configure cgroups, nftables, and fanotify. It runs as a root systemd service (`netscoped.service`).
2. **Socket Permissions:** The control socket `/run/netscope/control.sock` is created with mode `0660` owned by `root:netscope`. Unprivileged users must be members of the `netscope` group to interact with the daemon.
3. **Peer Credential Validation:** `netscoped` checks `SO_PEERCRED` on every socket connection. A non-root client can only manage profiles matching their own UID (`target_uid == peer_uid`).
4. **Fallback Safety:** If a client crashes, `Hold::Peer` prevents rule leaks. If the daemon crashes, `netscoped.service` auto-restarts and reconciles the routing rules and cgroup state.
