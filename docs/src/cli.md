# CLI reference

`netscope` is the unprivileged command-line client. It talks to `netscoped` over a Unix socket and never manipulates nftables or routing itself, except for the explicit `cleanup` recovery command.

```text
netscope [GLOBAL OPTIONS] <COMMAND>
```

## Global options

| Option | Meaning |
|---|---|
| `--socket <path>` | Hidden. Override the control socket. For tests and non-default daemon paths. |
| `--uid <n>` | Hidden, root-only. Target user ID for `add`. When omitted by root, `SUDO_UID` is used. |
| `-h, --help` | Print help. |
| `-V, --version` | Print the client version. |

A regular user in the `netscope` group does not pass `--uid`; their profile belongs to the connecting UID. Root passes `--uid` (or relies on `SUDO_UID`) to create a profile for another user; root `add` with neither fails with exit `2`. A non-root user cannot use `--uid`.

## Exit codes

| Code | Meaning | Typical message |
|---|---|---|
| `0` | Success. | — |
| `1` | Runtime or daemon error, including invalid daemon JSON, API version mismatch, nftables/routing/cgroup failure, an unknown profile, a duplicate profile, the profile limit, a daemon policy rejection that is not a permission error, or a failed `doctor` check. | `netscope: <error>` |
| `2` | Usage or validation error caught by the client: bad flag combination, invalid profile ID, invalid CIDR, invalid gateway, unresolvable `--exe` or `--wine`, a `--process` value that is empty or contains a path separator, invalid Steam app ID, `--no-redact` without `--acknowledge`, or a non-root `--uid`. | `netscope: <error>` |
| `3` | Daemon unavailable, or `cleanup` attempted while the daemon is still running. | `netscope: daemon not running; start with: sudo systemctl start netscoped` |
| `4` | Permission denied, a profile owned by another user, a `target_uid` that does not match the caller, or `support-bundle` invoked without root. | `netscope: permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER` |

`support-bundle` without root exits `4` with `netscope: support-bundle requires root: sudo netscope support-bundle`, unless `--no-redact` is given without `--acknowledge`, which exits `2` first. A non-root `doctor` fails its `root` check and exits `1`, not `4`.

Scripts should branch on `0` versus non-zero, and use `3` to distinguish "daemon down" from a rejected request.

## `status`

```text
netscope status [--json]
```

Prints the daemon version, pid, kernel, cgroup root, and one row per profile. The text form has a daemon header and the same columns as `list`:

```text
DAEMON  netscoped 0.3.0  pid 1234  kernel 6.11.0-arch1-1
CGROUP  /sys/fs/cgroup/netscope
NAME       MODE    ENABLED  TARGET                      ATTACHED  CONSUMERS         POLICIES          PIDS
blocked    filter  yes      /usr/bin/curl               pre-exec  cli               cli:filter        4242
game       route   yes      wine:/games/Game/Game.exe   pre-open  cli               cli:route         5150
running    route   yes      name:Overwatch.exe          late      cli               cli:route         6120
shared     route   yes      name:Overwatch.exe          pre-exec  dropship,exitlink exitlink:route    7001
```

A profile with ordered links prints one indented line per link after its row:
`link <iface> <gateway> <phase> <rtt> <active>`, where `-` stands in for a
missing gateway or RTT and `active` marks the link currently carrying the
default route. The state path and config path are available in `--json` output.

`ATTACHED` is `pre-exec` when only the native exec hook placed processes, `pre-open` when only the Wine open hook did, and `late` when only the poll fallback did. It is `mixed` when a pre-attach source (`pre-exec` or `pre-open`) and the poll fallback are both present, and `none` when no process is attached. A Wine profile shows its target as `wine:<path>`; a process-name profile shows `name:<name>`. `PIDS` is a comma-separated list.

`status` exits `3` when the daemon is not reachable.

## `list`

```text
netscope list [--json]
```

Prints the profile table without the daemon header. Disabled profiles are included. `list` also exits `3` when the daemon is unavailable.

## `add`

```text
netscope add <name> --exe <path> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS] | --link <spec> [ROUTE OPTIONS])
netscope add <name> --wine <path> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS] | --link <spec> [ROUTE OPTIONS])
netscope add <name> --process <name> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS] | --link <spec> [ROUTE OPTIONS])
netscope add <name> --steam <appid> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS] | --link <spec> [ROUTE OPTIONS])
```

Creates a profile. Exactly one of `--exe`, `--wine`, `--process`, and `--steam` is required, and exactly one of `--filter`, `--route`, and `--link` is required.

| Option | Applies to | Meaning |
|---|---|---|
| `--exe <path>` | Native apps | Executable to select. Resolved against the CLI's current directory, then canonicalized. |
| `--wine <path>` | Wine/Proton apps | Windows PE to select. Must be an absolute path. The daemon canonicalizes it and requires an `MZ` header. |
| `--process <name>` | Running apps | Process name or argv basename. No install path. Matches `comm` and command-line basenames case-insensitively; a trailing `.exe` is optional. |
| `--steam <appid>` | Steam apps | Numeric Steam app ID. Matches the app and its children. |
| `--filter <drop\|allow>` | Filter profiles | Default action. |
| `--allow-cidr <cidr>` | `--filter drop` | Destination to keep reachable. Repeatable. |
| `--deny-cidr <cidr>` | `--filter allow` | Destination to drop. Repeatable; at least one is required. |
| `--route <iface>` | Route profiles | Tunnel interface. |
| `--link <spec>` | Route profiles | Ordered link: `<iface>`, `<iface>@<ipv4>`, `<iface>#<ipv6>`, or `<iface>@<ipv4>#<ipv6>`. Repeatable, up to 8; the first healthy link carries the default route. Conflicts with `--route`. |
| `--gateway <ipv4>` | `--route` | IPv4 next hop. |
| `--gateway6 <ipv6>` | `--route --allow-ipv6` | IPv6 next hop. |
| `--include-lan` | `--route` | Route LAN destinations instead of bypassing them. |
| `--allow-ipv6` | `--route` | Carry IPv6; without it, IPv6 is dropped. |
| `--udp` | `--route` | Mark only IPv4 UDP; TCP keeps its normal route. |
| `--except-port <port>` | `--route --udp` | UDP destination port that stays direct. Repeatable, up to 32. |
| `--except-sport <port>` | `--route --udp` | UDP source port pinned direct. Repeatable, up to 64. |
| `--except <cidr>` | `--route` | Destination that stays direct. Repeatable, up to 30. |

Rules enforced before the daemon is asked:

- Name: `^[a-z0-9][a-z0-9-]{0,31}$`.
- Exactly one target: `--exe`, `--wine`, `--process`, or `--steam`. Combining them is a usage error.
- `--wine` takes an absolute path to a regular file that starts with `MZ`. The daemon canonicalizes the path and stores its device and inode.
- `--process` takes a name, not a path. It is matched against the process `comm` and its executable basename, and against any argv basename of a Wine loader; `Overwatch`, `Overwatch.exe`, and `overwatch.exe` are the same target. A new Wine/Proton launch is caught by the loader hold before its first socket; an already-running process attaches on the poll and has its existing sockets marked.
- `--allow-cidr` is rejected with `--filter allow`.
- `--deny-cidr` is rejected with `--filter drop`, and `--filter allow` needs at least one.
- `--link` conflicts with `--route`, `--gateway`, and `--gateway6`; per-link gateways belong inside the spec. Interfaces must be unique and at most eight are accepted.
- An IPv6 half (`#<ipv6>`) requires `--allow-ipv6`.
- `--gateway` is rejected outside `--route`.
- `--gateway6` is rejected without `--allow-ipv6`.
- `--include-lan`, `--allow-ipv6`, `--udp`, `--except-port`, `--except-sport`, and `--except` are accepted with either `--route` or `--link`.
- `--except-port` requires `--udp` and takes 32 ports; port `0` is rejected.
- `--except-sport` requires `--udp` and takes 64 ports; port `0` is rejected. Pinned sockets are never marked and their packets are accepted before the mark rule, so a flow that already existed when the profile opened keeps its normal route. A socket keeps its source port for its whole life, so the pin holds until the process exits.
- `--except` takes up to 30 CIDRs. The daemon installs each as an `ip rule` to `main` at a lower priority than the mark rule.

On success the daemon creates the cgroup, the nftables table, and, for route profiles, the policy rule and routes. If the app was already running and got attached late, the CLI prints:

```text
existing sockets marked; restart is not required
```

```sh
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop
sudo netscope --uid "$(id -u)" add routed --exe /usr/bin/game --route tun0 --include-lan
sudo netscope --uid "$(id -u)" add game --wine /games/Game/Game.exe --filter drop
sudo netscope --uid "$(id -u)" add running-game --process Overwatch.exe --route tun0
sudo netscope --uid "$(id -u)" add game-udp --process Overwatch.exe --route tun0 --udp --except-port 53
sudo netscope add steam-game --steam 730 --filter drop --allow-cidr 203.0.113.0/24
```

The last example assumes the user is in the `netscope` group and has re-logged in. On success, `add` prints `added <name>`; with a late attach it prints the restart warning on the next line.

For a Wine target the profile attaches when a Wine process opens the PE, which is before the game runs. Launch the game the same way you would without netscope — there is no wrapper. A `--process` target holds the Wine/Proton loaders and attaches a new launch before its first socket; an already-running process attaches on the poll and is reported as `late`. See [Wine and Proton targets](how-it-works.md#wine-and-proton-targets) and [Name targets](how-it-works.md#name-targets).

## `open`, `policy`, `close`, and `resolve`

```text
netscope open --consumer <id> [--name <profile>] <TARGET> [POLICY]
netscope policy <profile> --consumer <id> (--filter ... | --route ... | --link ...)
netscope close <profile> --consumer <id>
netscope resolve (--profile <id> | <TARGET>)
```

`open` creates or joins a shared profile for `(target, target uid)`. Two
consumers with the same target and uid get the same profile and cgroup. The
first consumer creates the scope; the last `close` removes it. `--name` names a
new profile; without it the daemon generates one from the target and uid (for
example `overwatch-u1000`). The CLI holds its claim persistently, so it
survives the command. Peer claims belong to API clients that keep their control
connection open; they are not available from the one-shot CLI. The target flags
are the same as `add`, and a policy may be attached in the same command.

`policy` replaces one consumer's policy. A shared profile can carry several
filter policies but only one route policy; a second consumer asking for a route
gets an error. Filters run before the route mark, so a drop
from any consumer is terminal for that packet and an accepted packet continues
to the route mark.

`close` releases one consumer and reports whether the profile was removed.
`resolve` finds the shared profile from an id or a target and prints it. If
`open` succeeds but its policy is rejected, the claim is kept: retry
`netscope policy`, or `netscope close` it.

```sh
sudo netscope --uid "$(id -u)" open --consumer exitlink --name overwatch --process Overwatch.exe --route tun0
sudo netscope --uid "$(id -u)" open --consumer dropship --process Overwatch.exe --filter allow \
  --deny-cidr 64.224.26.0/23
sudo netscope policy overwatch --consumer exitlink --route tun0 \
  --except 203.0.113.0/24
sudo netscope --uid "$(id -u)" open --consumer exitlink --name failover \
  --process Overwatch.exe --link enp7s0f4u1 --link wwan0@10.64.0.1
sudo netscope close overwatch --consumer dropship
```

See [Shared scopes](shared-scopes.md).

## `remove`

```text
netscope remove <name>
```

Deletes the profile's nftables table, policy rule, routes, and cgroup, then prints `removed <name>`. Removing a profile that does not exist is a daemon error (`1`). Removing another user's profile as a non-root user is `4`.

## `enable` and `disable`

```text
netscope enable <name>
netscope disable <name>
```

`disable` stops enforcement for the profile while keeping its definition and cgroup; `enable` restores it. Disabling a route profile removes its mark rules, so its traffic returns to the main table. Both print `enabled <name>` or `disabled <name>` and validate ownership like `remove`.

## `refresh`

```text
netscope refresh
```

Forces an immediate target re-stat and attach pass instead of waiting for `refresh_interval_secs`. It re-resolves each `--exe` or `--wine` target's device and inode, attaches already-running matching processes (including name targets), then prints `refreshed`. For a Wine target whose file changed, it moves the fanotify mark to the new inode. It does not repair a deleted nftables table; the daemon's health loop does that.

## `doctor`

```text
netscope doctor [--json]
```

Runs eight checks: `root`, `kernel`, `cgroup v2`, `tools` (nftables and iproute2), `daemon` (connectivity and API version), `control socket` (group `netscope`, mode `0660`, connectable), `state + config`, and `profiles` (per-profile runtime). It exits `0` only when no check fails; warnings do not change the exit code.

A non-root run **fails the `root` check and exits `1`**. Other privileged probes that need root report `SKIP`. Run it with `sudo netscope doctor` for the complete report.

`--json` prints a machine-readable report. It is suitable for a bug report and is also included in the support bundle.

## `support-bundle`

```text
netscope support-bundle [--output <path>] [--include-logs] [--include-config]
netscope support-bundle --no-redact --acknowledge
```

Collects diagnostics into a compressed archive. It is root-only; a non-root run exits `4`, except `--no-redact` without `--acknowledge`, which exits `2` before the root check. Without `--output`, it writes `/tmp/netscope-support-<UTC>.tar.zst`.

`logs.txt` and `config.toml` are excluded unless you pass `--include-logs` and `--include-config`. Redaction is on by default; `--no-redact` is refused unless `--acknowledge` is also given, and is intended only for a private reproduction.

On success it prints:

```text
support bundle: <path>
review before uploading
```

The bundle is mode `0600` and chowned back to `SUDO_UID:SUDO_GID` under sudo; review it before uploading. See [Support bundle](support-bundle.md).

## `logs`

```text
netscope logs [-n <lines>]
```

Prints the most recent daemon log lines from the journal. The default is 50; `-n` changes the count. It does not follow, and it does not clear the journal.

## `cleanup`

```text
netscope cleanup --all [--purge]
```

Recovery command for host state left behind by a daemon that could not clean up. It is root-only, requires `--all`, and bypasses the daemon. If the daemon is reachable, it refuses and exits `3`:

```text
cleanup requires the daemon stopped: sudo systemctl stop netscoped
```

`--purge` additionally deletes the configured state file (`/var/lib/netscope/state.json` by default) and `/etc/netscope/config.toml`. Without it, only runtime state is cleaned: every `netscope_*` nftables table, every policy rule and flushed route table in the `20000`–`20031` range, and every profile cgroup under the configured cgroup root. The profile definitions therefore survive and are re-applied when the daemon starts. Cleanup never deletes the control socket, so a stopped daemon cannot be contacted through it.

On success it prints `cleanup complete`. A failed cleanup step prints the step and exits `1`.

```sh
sudo systemctl stop netscoped
sudo netscope cleanup --all
sudo systemctl start netscoped
```

## `--json` output

`status`, `list`, and `doctor` accept `--json`. The client prints the response's `data` field only, pretty-printed, with no success envelope and no error field. Errors are still printed to standard error with the exit code above.

## Examples by outcome

| Command | Exit | Why |
|---|---|---|
| `netscope status` | `0` | Daemon reachable. |
| `netscope status` with the service stopped | `3` | No socket. |
| `netscope add bad_name --exe /bin/true --filter drop` | `2` | Uppercase and underscore are invalid in a profile ID. |
| `netscope add x --exe /bin/true --filter allow` | `2` | `allow` needs at least one `--deny-cidr`. |
| `netscope add x --exe /nope --filter drop` | `2` | Path cannot be resolved. |
| `netscope add x --exe /bin/true --route tun9` | `1` | The daemon cannot install a route through a missing interface. |
| `netscope add x --exe /bin/true --filter drop` as a non-group user | `4` | Socket permission denied. |
| `sudo netscope cleanup --all` while `netscoped` runs | `3` | Cleanup requires the daemon stopped. |
