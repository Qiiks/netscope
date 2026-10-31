# How it works

netscope gives one application a cgroup identity and writes nftables rules that match that identity. The application is launched normally; there is no wrapper, `LD_PRELOAD`, or proxy setting.

## The pipeline

1. **Add a profile.** The CLI canonicalizes `--exe` and sends its path to the daemon. The daemon resolves the path to a device and inode and stores that identity with the profile. A `--wine` profile does the same for a Windows PE, after checking that the file starts with `MZ`. A `--process` profile stores only the process name. A Steam profile stores the app ID instead.
2. **Catch the next exec or open.** `fanotify` watches for `exec` of the selected native inode, or for the first open of the selected PE by a Wine/Proton loader. The kernel holds the operation until the daemon answers, which gives the daemon time to create `/sys/fs/cgroup/netscope/<profile>` and move the new process into it. A name target holds the Wine/Proton loader binaries and matches the loader's launcher ancestry or its command line against the target name, so a new game launch is also caught before its first socket. An already-running process is attached by the poll.
3. **Match on the cgroup or the profile mark.** nftables rules use `socket cgroupv2` for processes moved before their first socket. A process attached after it already held sockets has those sockets marked with the profile's firewall mark, and a second `socket mark` rule matches them. A process cannot escape the cgroup match by renaming itself or by being re-parented.
4. **Filter or mark.** A filter profile accepts or drops matching packets. A route profile sets a firewall mark on them.
5. **Route by mark.** For route profiles, an `ip rule` sends marked packets to a dedicated routing table containing the tunnel route and a higher-metric blackhole default.

The process stays in the profile cgroup for its lifetime, and children inherit it. That is why launching a game launcher that later starts the game still works: the launcher's children remain in the same cgroup.

## Profile identity

Each profile gets a bounded set of host identifiers:

| Value | Base | Per-profile | Limit |
|---|---|---|---|
| Firewall mark | `0x4e53` | `+ index` | 32 profiles |
| Routing table | `20000` | `+ index` | 32 profiles |
| Rule priority | `1000` | `+ index × 32` | 32 profiles |
| nftables table | — | `netscope_<id>` | one per profile |
| cgroup | `/sys/fs/cgroup/netscope` | `/<id>` | one per profile |

A profile ID is 1–32 characters: lowercase ASCII letters, digits, and `-`, starting with a letter or digit. The nftables table name replaces `-` with `_`, so `my-game` becomes `netscope_my_game`.

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

## Name targets

A `--process <name>` target needs no install path. It covers both a new launch
and an already-running app:

- The daemon scans `/proc` on the poll interval and reads each process's
  `comm` and command line.
- A process matches when its `comm` or its executable (`argv[0]`) basename
  equals the name. A Wine loader also matches when any argv token's basename
  equals it, because Wine carries the PE there. Matching is case-insensitive
  and drops a trailing `.exe`, so `Overwatch`, `Overwatch.exe`, and
  `overwatch.exe` select the same process; `C:\Games\Overwatch.exe` matches as
  a Wine argv token, but a path is not an accepted target value.
- For a new Wine/Proton launch, the daemon holds the loader binaries with
  `FAN_OPEN_EXEC_PERM`. If the loader's launcher ancestry or the loader's own
  command line names the target, the loader is moved into the cgroup before it
  runs, and the game inherits it. The daemon then learns the PE path from that
  command line and holds the PE open, so the next launch is caught even if the
  loader path changes.
- An already-running process is attached on the next poll. Sockets it already
  held are marked with the profile's firewall mark, so their next packets
  follow the profile too.
- `status` reports the target as `name:<name>` and the attach source as
  `pre-exec` for a loader-held launch or `late` for a running process.

Name targets cannot distinguish two processes with the same name; both are
attached. The loader hold only covers Wine/Proton binaries the daemon can find
and whose launcher ancestry or command line names the target; a custom build
outside the scanned directories, or a launcher that does not name the game,
falls back to late attach. The PE hold is learned only from an absolute, `Z:\`, or `C:\`
path in that command line.

## Late attachment (poll fallback)

If fanotify cannot be used — for example because the kernel or a security policy refuses the permission group — the daemon scans `/proc` on an interval (`poll_interval_ms`, default 1000 ms). It attaches matching processes and their children after the fact. For a native target it matches the executable path. For a Wine target it requires a Wine process and matches the configured PE path against the process command line, accepting a Windows-style `Z:\...` path and the `C:\...` form that maps under `/drive_c/`. Name targets use this path when the process was already running.

Late attachment covers sockets that already exist. After moving the process
into its cgroup, the daemon walks `/proc/<pid>/fd`, duplicates each descriptor
with `pidfd_getfd`, and sets `SO_MARK` to the profile's mark on every IPv4 and
IPv6 socket it finds. Changing the mark resets the kernel's cached destination,
so the next packet is routed through the profile's table. The nftables chain
matches those sockets with `socket mark` in addition to `socket cgroupv2`.
Name targets use this path for a process that was already running; a new Wine
launch is caught by the loader hold instead.

This needs `CAP_NET_ADMIN` and the ability to inspect the target process, which
the root daemon has. If a descriptor cannot be reached, the attach is reported
with a `mark profile=... error=...` log line and that socket keeps its original
route. A daemon restart marks existing sockets again on the next poll.

The daemon reports a late attach through `status`, and the CLI prints a
warning when the target was already running:

```text
existing sockets marked; restart is not required
```

Removing a profile clears the mark from sockets that still carry it, so a
later profile reusing the same mark cannot inherit them. A daemon restart keeps
the marks that are already set and re-marks the target on the next poll.

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

A profile's nftables table hooks `output` in the `inet` family. Rules are evaluated in order:

- **`--filter drop`:** drop IPv4 traffic except loopback `127.0.0.0/8` and the `--allow-cidr` destinations; drop IPv6 except `::1/128` and allowed IPv6 destinations; drop non-IP traffic too. Loopback is always allowed.
- **`--filter allow`:** drop each `--deny-cidr`; the chain policy accepts everything else. At least one deny CIDR is required, otherwise the profile would do nothing.

Only packets with a socket in the profile's cgroup or carrying the profile's
mark are matched. See [Filter mode](modes/filter.md).

A shared profile can carry several filter policies, one per consumer. They are
emitted before the route mark. A drop from any consumer is terminal; an accepted
packet falls through to the route mark, so a filter never silently replaces a
route. See [Shared scopes](shared-scopes.md).

## Route evaluation

A route profile's table accepts loopback, optionally accepts LAN destinations, optionally drops IPv6, then sets the profile's mark. A policy rule sends marked packets to the profile's table. That table has:

- a real default route through the configured interface at metric 100;
- a blackhole default at metric 1000.

When the interface is up, the real route wins. When it is down, the blackhole matches instead of falling back to the main table. Each route exception adds an `ip rule` to `main` at a lower priority number than the profile's mark rule, so it is evaluated first and that destination stays direct while everything else uses the profile's table. See [Route mode](modes/route.md) for the exact fail-open cases.

## What netscope does not do

- No kernel module and no eBPF program. Everything is cgroup v2, fanotify, nftables, and policy routing.
- No packet capture, no DNS rewriting, no proxy, no remote API, and no web UI.
- No system-wide mode: netscope scopes selected applications, not the whole machine.
- No coverage for traffic forwarded on behalf of another host, kernel-generated packets without a local socket, or sockets that cannot be inspected by the root daemon.

## Next

- [Filter mode](modes/filter.md)
- [Route mode](modes/route.md)
- [Security](security.md)
