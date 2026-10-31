# How it works

netscope gives one application a cgroup identity and writes nftables rules that match that identity. The application is launched normally; there is no wrapper, `LD_PRELOAD`, or proxy setting.

## The pipeline

1. **Add a profile.** The CLI canonicalizes `--exe` and sends its path to the daemon. The daemon resolves the path to a device and inode and stores that identity with the profile. A `--wine` profile does the same for a Windows PE, after checking that the file starts with `MZ`. A Steam profile stores the app ID instead.
2. **Catch the next exec or open.** `fanotify` watches for `exec` of the selected native inode, or for the first open of the selected PE by a Wine/Proton loader. The kernel holds the operation until the daemon answers, which gives the daemon time to create `/sys/fs/cgroup/netscope/<profile>` and move the new process into it.
3. **Match on the cgroup.** nftables rules use `socket cgroupv2`, not a process name, PID, or executable string. A process cannot escape the match by renaming itself or by being re-parented.
4. **Filter or mark.** A filter profile accepts or drops matching packets. A route profile sets a firewall mark on them.
5. **Route by mark.** For route profiles, an `ip rule` sends marked packets to a dedicated routing table containing the tunnel route and a higher-metric blackhole default.

The process stays in the profile cgroup for its lifetime, and children inherit it. That is why launching a game launcher that later starts the game still works: the launcher's children remain in the same cgroup.

## Profile identity

Each profile gets a bounded set of host identifiers:

| Value | Base | Per-profile | Limit |
|---|---|---|---|
| Firewall mark | `0x4e53` | `+ index` | 32 profiles |
| Routing table | `20000` | `+ index` | 32 profiles |
| Rule priority | `1000` | `+ index` | 32 profiles |
| nftables table | — | `netscope_filter_<id>` or `netscope_route_<id>` | one per profile |
| cgroup | `/sys/fs/cgroup/netscope` | `/<id>` | one per profile |

A profile ID is 1–32 characters: lowercase ASCII letters, digits, and `-`, starting with a letter or digit. The nftables table name replaces `-` with `_`, so `my-game` becomes `netscope_filter_my_game`.

## Pre-exec attachment

For native ELF targets the primary path is pre-exec:

- The daemon registers the profile's inode with a fanotify group that has permission events enabled.
- When the kernel reports `FAN_OPEN_EXEC_PERM` for that inode, the daemon reads the PID, verifies the process still matches, creates the cgroup, writes the thread-group ID to `cgroup.procs`, and allows the exec.
- The daemon records the process start time before and after the move. If the PID was reused during the operation, it restores the original cgroup and refuses the attach rather than capturing an unrelated process.

Kernel 5.13 or newer is required because earlier kernels cannot hold an exec for this decision. Root is required to create the cgroup and to open the fanotify permission group.

## Wine and Proton targets

A Windows program does not `exec` a new image under Wine. The Wine loader maps the PE and runs its code; the shared `wineserver` may open the PE on the loader's behalf. There is no exec of the PE to hold, so `--wine` uses a different mark:

- The daemon marks the PE inode with `FAN_OPEN_PERM`, the permission event for an ordinary open, instead of `FAN_OPEN_EXEC_PERM`.
- When any process opens the marked PE, the kernel holds the open. If the opener is a Wine process whose command line names the PE, the daemon attaches that process. If the opener is `wineserver` or another Wine helper, the daemon scans for a Wine process whose command line names the PE and attaches that one instead. It never attaches `wineserver`.
- If no matching process exists yet, the daemon allows the open and the poll fallback attaches the process later.
- The game process has not run game code until the PE open is allowed, so the game's sockets are created after the move.
- `status` reports the source as `pre-open`.

A Wine process is an executable whose basename is `wine`, `wine64`, `wine-preloader`, or `wine64-preloader`, or whose basename contains `wine-preloader`. Only a Wine process whose command line names the selected PE is attached. Any other program that opens the same PE — a file manager, a scanner, a copy — is allowed and left unscoped, because for those processes the PE is just a data file.

The mark is on the file rather than on an exec, so it also catches a load by a loader that was already running, and a second launch of the same game. Select the PE path that Wine actually opens. For Proton that is usually the `.exe` under `steamapps/common`; if the game is launched from a copy inside the prefix, select that copy instead. `--steam <appid>` remains available for matching a Steam app by id.

Wine itself is not installed by netscope and is not required to configure a profile. Adding the profile fails if the path is not absolute, cannot be canonicalized, is not a regular file, or does not start with `MZ`.

## Late attachment (poll fallback)

If fanotify cannot be used — for example because the kernel or a security policy refuses the permission group — the daemon scans `/proc` on an interval (`poll_interval_ms`, default 1000 ms). It attaches matching processes and their children after the fact. For a native target it matches the executable path. For a Wine target it requires a Wine process and matches the configured PE path against the process command line, accepting a Windows-style `Z:\...` path and the `C:\...` form that maps under `/drive_c/`.

Late attachment has an unavoidable gap: a socket opened before the process was moved keeps its original cgroup, so it is not matched by the profile's rules. This also applies to Wine targets, where the loader may open sockets while starting the game. The daemon reports the profile as `late` and the CLI prints a warning when it attaches to an already-running app:

```text
existing connections unaffected; restart the app for full coverage
```

Restarting the application closes that gap. Existing sockets are never retroactively moved.

## Background loops

Three loops keep a profile current:

| Loop | Interval | Work |
|---|---|---|
| Poll | `poll_interval_ms`, default 1000 ms | Scan `/proc` and attach matching processes that the exec or open hook did not catch. |
| Refresh | `refresh_interval_secs`, default 5 s | Re-resolve each native or Wine target's device and inode, move its fanotify mark if the file changed, then attach matching processes. |
| Health | 10 s, fixed | Verify each enabled profile's cgroup, nftables table, policy rule, routes, and fanotify mark; recreate anything missing. |

The health loop is what repairs a table or rule deleted by hand, within about ten seconds. `netscope refresh` does not run a repair pass; it re-stats targets and attaches processes, which is useful after a binary is replaced.

Because the health loop recreates missing state, removing a profile with `netscope remove` is the supported way to stop scoping. Deleting its nftables table by hand while the profile is enabled just makes the daemon recreate it.

## Filter evaluation

A filter profile's table hooks `output` in the `inet` family. Rules are evaluated in order:

- **`--filter drop`:** accept IPv4 `127.0.0.0/8` and IPv6 `::1/128`, accept each `--allow-cidr`, then drop everything else.
- **`--filter allow`:** drop each `--deny-cidr`; the chain policy accepts everything else. At least one deny CIDR is required, otherwise the profile would do nothing.

Only packets with a socket in the profile's cgroup are matched. See [Filter mode](modes/filter.md).

## Route evaluation

A route profile's table accepts loopback, optionally accepts LAN destinations, optionally drops IPv6, then sets the profile's mark. A policy rule sends marked packets to the profile's table. That table has:

- a real default route through the configured interface at metric 100;
- a blackhole default at metric 1000.

When the interface is up, the real route wins. When it is down, the blackhole matches instead of falling back to the main table. See [Route mode](modes/route.md) for the exact fail-open cases.

## What netscope does not do

- No kernel module and no eBPF program. Everything is cgroup v2, fanotify, nftables, and policy routing.
- No packet capture, no DNS rewriting, no proxy, no remote API, and no web UI.
- No system-wide mode: netscope scopes selected applications, not the whole machine.
- No coverage for traffic forwarded on behalf of another host, kernel-generated packets without a local socket, or sockets opened before attachment.

## Next

- [Filter mode](modes/filter.md)
- [Route mode](modes/route.md)
- [Security](security.md)
